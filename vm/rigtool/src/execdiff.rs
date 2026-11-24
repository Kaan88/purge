//! `rigtool execdiff`: the executed-effects check of an exec run (M2-RIG-EXECDIFF; ENGINE_PLAN.md §1.3
//! `guard_escapes`, `collateral`; §10.2).
//!
//! Inputs: snapshots before and after the exec (`snap`), the session's `journal.jsonl` and `report.json`
//! (`purge.exec/1`), the trap / fixture manifests (`purge.rig.m2traps/*`, `purge.rig.m2fixtures/*`), optionally
//! the ambient set and deep snapshots before and after.
//!
//! Definitions (all counts in the output's `counts`):
//! - **collateral**: a record of `diff(before, after)` that was removed (`-`) or changed (`~`) and is not
//!   authorised. Authorised are: (op) a record covered by the target of a journal op whose effective outcome is
//!   `Done` or `Vanished`: a path at or inside a `QuarantineMove` target, the exact `RemoveDirIfEmpty`
//!   directory, a key or value at or inside a `DeleteKeyTree` key, the exact `DeleteKeyIfEmpty` key, the exact
//!   `DeleteValue` value (removed) and the exact `EditSegment` value (changed); M1b typed objects, removed records
//!   only: a key or value at or inside `Services\<name>` of a `DeleteService`, the exact `FirewallRules` value of a
//!   `DeleteFirewallRule`, the exact task file of a `DeleteTask` and keys or values at or inside its
//!   `TaskCache\Tree\<path>` key and, by the before snapshot's `Id`, `TaskCache\{Tasks,Plain,Logon,Boot,
//!   Maintenance}\{id}`; (pending-delete) a `DeleteService` left `PendingDelete`: its `DeleteFlag` value added or
//!   changed; (task-reregistered) for a `DeleteTask` whose Tree key is present before and after, exactly the
//!   TaskCache values the M1b spike lists as regenerated, and, when the op has an intent and the Tree `Id`
//!   changed, the task file itself changed with kind, attributes and reparse state unchanged (see
//!   `task_reregistrations`); (store) Purge's own stores:
//!   `C:\ProgramData\Purge`, the header's per-volume quarantine directories and any `X:\.purge-q`; (rig) the rig's
//!   own files (`items::RigRules`); (pending-rename) `Session Manager|PendingFileRenameOperations` when an op was
//!   left `PendingReboot` or reconciled; (engine-rm) the engine's own Restart Manager session state, keys and
//!   values at or under `HKU\<sid>\Software\Microsoft\RestartManager` (the lock query's documented side effect,
//!   RIG.md §11.8); (engine-rp) the VSS diagnostics the engine's restore point writes, keys and values at or
//!   under `HKLM\SYSTEM\<control set>\Services\VSS\Diag`, changed or added, never removed, and, only when the
//!   report's restore point is `Created`, the other records creating one writes, additions and changes only (the
//!   volume snapshot device instance and container value, the SystemRestoreProv WMI tracing key, `SPP` and
//!   `SystemRestore|LastIndex`, `DsmSvc\State|SessionNumber`, the `System Volume Information` mtime; see
//!   `is_engine_rp_created`); (engine-fw) only when the journal has a `Done` `DeleteFirewallRule`: the wfascim WMI
//!   tracing key, `SharedAccess\Epoch|Epoch` and `wfpdiag.etl`, additions and changes only (`is_engine_fw_delete`);
//!   (broker-exit) what Windows records when purge-broker.exe exits after a completed execute: its bam
//!   `UserSettings\<sid>` value (name ending `\Program Files\Purge\purge-broker.exe`) and its Compatibility
//!   Assistant `Store` value (named `C:\Program Files\Purge\purge-broker.exe`), additions and changes only
//!   (`is_broker_exit`; a null run's declined consent never ends the broker in its window, RIG.md §17.1);
//!   (windows-prefetch) ambient-class Windows bookkeeping: a `<drive>:\Windows\Prefetch\*.pf` file changed in size
//!   and/or LastWriteTime only, never added or removed (`is_windows_prefetch`; Purge's file ops only remove);
//!   (ambient) the ambient set: with an M2 set (`purge.rig.m2ambient/1`) only the exact op and
//!   record seen in the null runs, or its token pattern, never a subtree; (parent) a directory whose only change is
//!   its LastWriteTime, or a key whose only changes are LastWriteTime / value count / subkey count, when an
//!   authorised record was added or removed directly inside it.
//! - **unexplained**: an added (`+`) record that is not authorised. Reported, never failing on its own.
//! - **guard_escapes**: canaries of the manifests (protected objects) that are missing or changed after the run:
//!   by the snapshots (file: kind, size, attributes, LastWriteTime, reparse tag; key: every value's type and data
//!   hash; value: type and data hash) and, when given, by the deep snapshots (file: content SHA-256 equal to the
//!   manifest's, no reparse tag, and with `--deep-before` every other deep field except LastWriteTime and the
//!   8.3 name; key and value: type, length and SHA-256 of every value, link flag, SDDL). A canary that no input
//!   can verify is `unverified`, which also fails the run.
//! - **missing_effects**: journal ops with effective outcome `Done` whose effect does not show in the after
//!   snapshot (the path, key or value is still there; an edited value has the same data).
//! - **changed_not_done**: ops with any other outcome whose target is gone or changed anyway (unless a removed
//!   op above it took it).
//! - **trap_mismatches**: trap items of the selected groups whose outcome is neither the manifest's `expect`
//!   nor one of its `accept` outcomes, or that the run did not contain. An item whose `condition` the build
//!   record shows as unmet is `not-scored`.
//! - **inconsistencies**: report and journal disagree (op set, outcomes without a reconcile, counts, state).
//!
//! `ok` = guard_escapes, collateral, missing_effects, changed_not_done, trap_mismatches, unverified_canaries and
//! inconsistencies all zero. Exit code 1 otherwise.

use crate::ambient::AmbientSet;
use crate::canon;
use crate::deep::{DeepDoc, FileRec, KeyRec as DeepKey};
use crate::diff::{self, Change};
use crate::err::{Context, Result, bail};
use crate::fidelity::journal::{
    Counts as OutcomeCounts, ExecOp, JOp, Journal, Outcome, parse_journal, read_journal_text,
};
use crate::fidelity::read_deep;
use crate::items::RigRules;
use crate::jsonio;
use crate::snap::{LoadOpts, Snap};
use crate::target::{FW_RULES, SERVICES, TASKCACHE, TASKS_DIR, Target};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

pub const SCHEMA: &str = "purge.rig.execdiff/1";
/// purge-model `ExecReportSchema`.
pub const EXEC_REPORT_SCHEMA: &str = "purge.exec/1";
/// Purge's own store (install\install.ps1).
pub const PURGE_STORE: &str = "C:\\ProgramData\\Purge";
const SESSION_MANAGER: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager";
const PFRO: &str = "PendingFileRenameOperations";

pub struct ExecdiffArgs {
    pub before: PathBuf,
    pub after: PathBuf,
    pub journal: PathBuf,
    pub report: PathBuf,
    pub traps: Vec<PathBuf>,
    pub ambient: Option<PathBuf>,
    pub deep_before: Option<PathBuf>,
    pub deep_after: Option<PathBuf>,
    /// Trap item groups to score; empty = `main`.
    pub groups: Vec<String>,
    pub sid: Option<String>,
    pub out: PathBuf,
}

// ---------------------------------------------------------------------------------------------
// Exec report (purge-model `exec::session::ExecReport`)
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize, Clone, Debug)]
#[allow(dead_code)] // fields are read to check the document's shape
pub struct ExecReport {
    pub schema: String,
    pub session: String,
    pub app: String,
    pub plan_hash: String,
    pub selection_hash: String,
    pub state: String,
    pub started: u64,
    pub finished: u64,
    pub items: Vec<ReportItem>,
    pub counts: OutcomeCounts,
    pub backup_bytes: u64,
    pub pending_reboot: bool,
    pub restore_point: RestorePoint,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Deserialize, Clone, Debug)]
#[allow(dead_code)] // fields are read to check the document's shape
pub struct ReportItem {
    pub item: String,
    pub op: u32,
    pub target: Target,
    /// `None` for an item with no executor op in the engine version (it is listed, skipped).
    #[serde(default)]
    pub exec_op: Option<ExecOp>,
    pub outcome: Outcome,
    #[serde(default)]
    pub backup_bytes: u64,
    #[serde(default)]
    pub lockers: Vec<Value>,
}

/// purge-model `RestorePointOutcome` (tagged by `"kind"`).
#[derive(Deserialize, Clone, Debug)]
pub struct RestorePoint {
    pub kind: String,
}

pub fn parse_report(text: &str) -> Result<ExecReport> {
    let v: Value = serde_json::from_str(text)?;
    let schema = v.get("schema").and_then(Value::as_str).unwrap_or("");
    if schema != EXEC_REPORT_SCHEMA {
        bail!("report schema {schema:?}, want {EXEC_REPORT_SCHEMA}");
    }
    Ok(serde_json::from_value(v)?)
}

// ---------------------------------------------------------------------------------------------
// Trap / fixture manifests
// ---------------------------------------------------------------------------------------------

/// An expected outcome of a trap item (`EBlocked`, `ESkipped`, `EOutcome` in m2-traps.ps1).
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct Expect {
    pub outcome: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub blocker: Option<String>,
}

impl Expect {
    pub fn matches(&self, o: &Outcome) -> bool {
        self.outcome == o.name()
            && self.reason.as_deref().is_none_or(|r| o.reason() == Some(r))
            && self.blocker.as_deref().is_none_or(|b| o.blocker() == Some(b))
    }
    pub fn summary(&self) -> String {
        let mut s = self.outcome.clone();
        for x in [&self.reason, &self.blocker].into_iter().flatten() {
            s.push('/');
            s.push_str(x);
        }
        s
    }
}

#[derive(Clone, Debug)]
pub struct TrapItem {
    pub id: String,
    pub group: String,
    pub target: Target,
    pub action: String,
    pub expect: Expect,
    pub accept: Vec<Expect>,
    pub condition: Option<String>,
}

#[derive(Clone, Debug)]
pub struct BuildObj {
    pub k: String,
    pub path: String,
    pub ok: bool,
}

#[derive(Clone, Debug)]
pub struct Trap {
    pub id: String,
    pub gate: String,
    /// `None` = no build record (dry-run manifest).
    pub built: Option<bool>,
    pub build_objects: Vec<BuildObj>,
    pub items: Vec<TrapItem>,
    /// The directory a race helper (`helper.action` swap) replaces with a junction while the engine is paused
    /// (canonical path). Its own change and its parent's LastWriteTime are the helper's, not the engine's.
    pub helper_dir: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Canary {
    pub id: String,
    pub trap: String,
    /// `file`, `regkey` or `regvalue`.
    pub kind: String,
    pub path: String,
    pub name: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Manifest {
    pub source: String,
    pub dry_run: bool,
    pub traps: Vec<Trap>,
    pub canaries: Vec<Canary>,
}

fn s_of(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_string)
}

/// Parses a manifest. `{user-sid}` placeholders (dry-run manifests) are replaced by `sid` when known.
pub fn parse_manifest(text: &str, source: &str, sid: Option<&str>) -> Result<(Manifest, Vec<String>)> {
    let mut warnings = Vec::new();
    let text = match sid {
        Some(s) => text.replace("{user-sid}", s),
        None => text.to_string(),
    };
    let v: Value = serde_json::from_str(&text)?;
    let schema = v.get("schema").and_then(Value::as_str).unwrap_or("");
    if !schema.starts_with("purge.rig.m2traps/") && !schema.starts_with("purge.rig.m2fixtures/") {
        bail!("{source}: schema {schema:?} is not an m2 trap or fixture manifest");
    }
    let mut m = Manifest {
        source: source.to_string(),
        dry_run: v.get("dry_run").and_then(Value::as_bool).unwrap_or(false),
        ..Default::default()
    };
    for t in v.get("traps").and_then(Value::as_array).into_iter().flatten() {
        let id = s_of(t, "id").context("traps[].id")?;
        let build = t.get("build").filter(|b| b.is_object());
        let mut trap = Trap {
            gate: s_of(t, "gate").unwrap_or_default(),
            built: build.map(|b| b.get("ok").and_then(Value::as_bool).unwrap_or(false)),
            build_objects: build
                .and_then(|b| b.get("objects"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|o| BuildObj {
                    k: s_of(o, "k").unwrap_or_default(),
                    path: s_of(o, "path").unwrap_or_default(),
                    ok: o.get("ok").and_then(Value::as_bool).unwrap_or(false),
                })
                .collect(),
            items: Vec::new(),
            helper_dir: t
                .get("helper")
                .filter(|h| h.get("action").and_then(Value::as_str) == Some("swap"))
                .and_then(|h| s_of(h, "dir"))
                .map(|d| canon::canon_path(&d)),
            id: id.clone(),
        };
        for it in t.get("items").and_then(Value::as_array).into_iter().flatten() {
            let iid = s_of(it, "id").with_context(|| format!("trap {id}: items[].id"))?;
            let target: Target = serde_json::from_value(it.get("target").cloned().unwrap_or(Value::Null))
                .with_context(|| format!("trap item {iid}: target"))?;
            let expect: Expect = serde_json::from_value(it.get("expect").cloned().unwrap_or(Value::Null))
                .with_context(|| format!("trap item {iid}: expect"))?;
            let accept: Vec<Expect> = match it.get("accept") {
                None | Some(Value::Null) => Vec::new(),
                Some(a) => serde_json::from_value(a.clone()).with_context(|| format!("trap item {iid}: accept"))?,
            };
            if target.path().contains("{user-sid}") || target.path().contains("{localappdata}") {
                warnings.push(format!("{source}: trap item {iid}: unresolved placeholder in {}", target.path()));
            }
            trap.items.push(TrapItem {
                id: iid,
                group: s_of(it, "group").unwrap_or_else(|| "main".into()),
                target,
                action: s_of(it, "action").unwrap_or_default(),
                expect,
                accept,
                condition: s_of(it, "condition"),
            });
        }
        m.traps.push(trap);
    }
    for c in v.get("canaries").and_then(Value::as_array).into_iter().flatten() {
        let id = s_of(c, "id").context("canaries[].id")?;
        let kind = s_of(c, "kind").with_context(|| format!("canary {id}: kind"))?;
        if !matches!(kind.as_str(), "file" | "regkey" | "regvalue") {
            bail!("{source}: canary {id}: unknown kind {kind:?}");
        }
        let path = s_of(c, "path").with_context(|| format!("canary {id}: path"))?;
        let path = if kind == "file" { canon::canon_path(&path) } else { canon::canon_reg(&path, sid) };
        if path.contains("{user-sid}") {
            warnings.push(format!("{source}: canary {id}: unresolved placeholder in {path}"));
        }
        m.canaries.push(Canary {
            trap: s_of(c, "trap").unwrap_or_default(),
            name: s_of(c, "name"),
            sha256: s_of(c, "sha256"),
            id,
            kind,
            path,
        });
    }
    Ok((m, warnings))
}

// ---------------------------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Clone, Debug, PartialEq, Default)]
pub struct Inputs {
    pub before: String,
    pub after: String,
    pub journal: String,
    pub report: String,
    pub traps: Vec<String>,
    pub ambient: Option<String>,
    pub deep_before: Option<String>,
    pub deep_after: Option<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Default)]
pub struct Counts {
    pub guard_escapes: u64,
    pub collateral: u64,
    pub unexplained: u64,
    pub missing_effects: u64,
    pub changed_not_done: u64,
    pub trap_mismatches: u64,
    pub not_scored: u64,
    pub unverified_canaries: u64,
    pub unverified_effects: u64,
    pub inconsistencies: u64,
    /// Records of diff(before, after).
    pub diff_records: u64,
    /// Authorised diff records by reason: op, store, rig, pending-rename, engine-rm, engine-rp, engine-fw,
    /// broker-exit, ambient, parent, ...
    pub authorised: BTreeMap<String, u64>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct DiffRow {
    /// `-F`, `~K`, `+V`, ...
    pub change: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct CanaryRow {
    pub id: String,
    pub trap: String,
    pub kind: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `intact`, `changed`, `missing` or `unverified`.
    pub verdict: String,
    /// Inputs that verified it intact (`snap`, `deep`).
    pub verified_by: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ItemRow {
    pub id: String,
    pub group: String,
    pub target: String,
    pub action: String,
    pub expect: String,
    pub accept: Vec<String>,
    pub op: Option<u32>,
    pub candidate: Option<String>,
    pub actual: Option<String>,
    /// `pass`, `accepted`, `mismatch`, `not-run`, `not-built` or `not-scored`.
    pub verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    /// The op's effect verdict (see `effects`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect: Option<String>,
    /// The journal `done` record's `detail` (why the engine skipped the item), when it gives one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct TrapRow {
    pub id: String,
    pub gate: String,
    /// The manifest the trap comes from.
    pub manifest: String,
    /// `pass`, `fail` or `not-scored`.
    pub verdict: String,
    pub canaries: u64,
    pub canaries_intact: u64,
    pub guard_escapes: u64,
    pub canaries_unverified: u64,
    pub items: Vec<ItemRow>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct EffectRow {
    pub op: u32,
    pub item: String,
    pub kind: Option<String>,
    pub target: Option<String>,
    pub outcome: Option<String>,
    /// `ok`, `missing` (Done, not visible), `changed` (not Done, changed anyway) or `unverified`.
    pub verdict: String,
    pub detail: String,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ExecdiffReport {
    pub schema: String,
    pub inputs: Inputs,
    pub groups: Vec<String>,
    pub sid: Option<String>,
    pub session: String,
    pub plan_hash: String,
    pub journal_state: String,
    /// The report's restore point outcome kind.
    pub restore_point: String,
    pub ok: bool,
    pub counts: Counts,
    pub canaries: Vec<CanaryRow>,
    pub traps: Vec<TrapRow>,
    pub collateral: Vec<DiffRow>,
    pub unexplained: Vec<DiffRow>,
    pub effects: Vec<EffectRow>,
    pub inconsistencies: Vec<String>,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------------------------
// Check
// ---------------------------------------------------------------------------------------------

pub struct Ctx<'a> {
    pub a: &'a Snap,
    pub b: &'a Snap,
    pub journal: &'a Journal,
    pub report: &'a ExecReport,
    pub manifests: &'a [Manifest],
    pub ambient: Option<&'a AmbientSet>,
    pub deep_a: Option<&'a DeepDoc>,
    pub deep_b: Option<&'a DeepDoc>,
    /// Empty = `main`.
    pub groups: &'a [String],
    pub sid: Option<&'a str>,
}

/// An op as the checks use it: canonical target, ExecOp kind (journal intent, else the report's exec_op),
/// effective outcome.
struct OpT<'a> {
    j: &'a JOp,
    kind: Option<String>,
    target: Option<Target>,
    /// DeleteTask: the task's `TaskCache\Tree\<path>|Id` in the before snapshot (its `Tasks\{id}` key).
    task_id: Option<String>,
}

/// TaskCache keys that hold a task by its `{id}`: its definition and its trigger-category index entries.
const TASKCACHE_ID_KEYS: &[&str] = &["Tasks", "Plain", "Logon", "Boot", "Maintenance"];

fn task_tree(path: &str) -> String {
    format!("{TASKCACHE}\\Tree\\{}", path.trim_start_matches('\\'))
}

fn task_file(path: &str) -> String {
    format!("{TASKS_DIR}\\{}", path.trim_start_matches('\\'))
}

impl OpT<'_> {
    fn removed(&self) -> bool {
        self.j.removed()
    }

    /// The typed objects (M1b): what a deleted service, task or firewall rule takes with it. A record removed
    /// (`-`) at or inside `Services\<name>`; the firewall rule's value; the task's file (exactly), its
    /// `TaskCache\Tree\<path>` key and, by the before snapshot's `Id`, its `Tasks\{id}` and trigger-category keys.
    fn covers_typed(&self, kind: &str, t: &Target, c: &Change) -> bool {
        if c.op != '-' {
            return false;
        }
        match (kind, t) {
            ("DeleteService", Target::Service { name }) => {
                matches!(c.rec, 'K' | 'V') && canon::is_under_or_eq(&c.path, &format!("{SERVICES}\\{name}"))
            }
            ("DeleteFirewallRule", Target::FirewallRule { id }) => {
                c.rec == 'V'
                    && canon::ci_eq(&c.path, FW_RULES)
                    && c.name.as_deref().is_some_and(|n| canon::ci_eq(n, id))
            }
            ("DeleteTask", Target::Task { path }) => match c.rec {
                'F' => canon::ci_eq(&c.path, &task_file(path)),
                'K' | 'V' => {
                    canon::is_under_or_eq(&c.path, &task_tree(path))
                        || self.task_id.as_deref().is_some_and(|id| {
                            TASKCACHE_ID_KEYS
                                .iter()
                                .any(|k| canon::is_under_or_eq(&c.path, &format!("{TASKCACHE}\\{k}\\{id}")))
                        })
                }
                _ => false,
            },
            _ => false,
        }
    }

    /// A service the engine left `PendingDelete` (marked for deletion, its key stays until the last handle closes):
    /// the SCM's `DeleteFlag` value on its key, added or changed.
    fn covers_pending_delete(&self, c: &Change) -> bool {
        let (Some("DeleteService"), Some(Target::Service { name })) = (self.kind.as_deref(), self.target.as_ref())
        else {
            return false;
        };
        self.j.outcome.as_deref() == Some("PendingDelete")
            && c.rec == 'V'
            && matches!(c.op, '+' | '~')
            && canon::ci_eq(&c.path, &format!("{SERVICES}\\{name}"))
            && c.name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case("DeleteFlag"))
    }

    /// Does this op's target cover diff record `c` (see the module comment)?
    fn covers(&self, c: &Change) -> bool {
        let (Some(kind), Some(t)) = (self.kind.as_deref(), self.target.as_ref()) else {
            return false;
        };
        if c.op == '+' {
            return false;
        }
        if matches!(t, Target::Service { .. } | Target::Task { .. } | Target::FirewallRule { .. }) {
            return self.covers_typed(kind, t, c);
        }
        match (c.rec, t) {
            ('D' | 'F', Target::Path { path }) => match kind {
                "QuarantineMove" => canon::is_under_or_eq(&c.path, path),
                "RemoveDirIfEmpty" => canon::ci_eq(&c.path, path),
                _ => false,
            },
            ('K', Target::RegKey { path }) => match kind {
                "DeleteKeyTree" => canon::is_under_or_eq(&c.path, path),
                "DeleteKeyIfEmpty" => canon::ci_eq(&c.path, path),
                _ => false,
            },
            ('V', Target::RegKey { path }) => match kind {
                "DeleteKeyTree" => canon::is_under_or_eq(&c.path, path),
                "DeleteKeyIfEmpty" => canon::ci_eq(&c.path, path),
                _ => false,
            },
            ('V', Target::RegValue { path, name }) => {
                kind == "DeleteValue"
                    && c.op == '-'
                    && canon::ci_eq(&c.path, path)
                    && canon::ci_eq(c.name.as_deref().unwrap_or(""), name)
            }
            ('V', Target::RegMultiSzSegment { path, name, .. }) => {
                kind == "EditSegment"
                    && c.op == '~'
                    && canon::ci_eq(&c.path, path)
                    && canon::ci_eq(c.name.as_deref().unwrap_or(""), name)
            }
            _ => false,
        }
    }
}

fn is_braced_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 38
        && b[0] == b'{'
        && b[37] == b'}'
        && b[1..37]
            .iter()
            .enumerate()
            .all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { *c == b'-' } else { c.is_ascii_hexdigit() })
}

/// Identity of a diff record: (op, rec, folded path, folded value name).
type ChangeId = (char, char, String, String);

fn change_id(c: &Change) -> ChangeId {
    (c.op, c.rec, canon::fold(&c.path), c.name.as_deref().map(str::to_lowercase).unwrap_or_default())
}

/// The TaskCache records a re-registration of a deleted task rewrites (M1b spike, K10), and only those: for a
/// DeleteTask op whose `TaskCache\Tree\<path>` key is present before and after (the task was registered again),
/// - the Tree key's values the spike lists as regenerated (`task.taskcache_regenerated` `Tree|<name>`: `Id`, `SD`),
///   changed with the same type;
/// - the task's `Tasks\{id}` values the spike lists (`Tasks\{id}|<name>`: `DynamicInfo`, `Hash` changed with the
///   same type, `Triggers` with the same type and length), when the `Id` stayed;
/// - when the `Id` changed: `Tasks\{old}` removed and `Tasks\{new}` added, and each trigger-category key
///   `<category>\{old}` removed with `<category>\{new}` added, provided the old and new `Tasks` keys hold the same
///   value names and every value not listed by the spike has the same type and data.
///
/// - the task file `System32\Tasks\<path>` (exactly), changed, when the op has an intent (the run acted on the
///   task), the `Id` changed (a registration happened) and the file is a plain file before and after with the
///   same attributes and no reparse point: Task Scheduler writes it again; its content is vouched for by
///   fidelity (XML and SDDL).
///
/// Anything else (the task file in any other case, other TaskCache values, a category key that does not pair)
/// stays collateral.
fn task_reregistrations(
    ops: &[OpT],
    a: &Snap,
    b: &Snap,
    spike: &crate::fidelity::SpikeRules,
    warnings: &mut Vec<String>,
) -> HashSet<ChangeId> {
    let mut out = HashSet::new();
    let tree_names = spike.regenerated("Tree");
    let task_names = spike.regenerated("Tasks\\{id}");
    let id_of = |s: &Snap, tree: &str| {
        s.value(tree, "Id").map(|v| v.preview.trim().to_string()).filter(|id| is_braced_guid(id))
    };
    let listed = |names: &[String], n: &str| names.iter().any(|x| x.eq_ignore_ascii_case(n));
    // Same type; Triggers also the same length (the spike: 5 bytes of the trigger blob change, its size stays).
    let regen_ok = |n: &str, x: &crate::snap::ValRec, y: &crate::snap::ValRec| {
        x.typ == y.typ && (!n.eq_ignore_ascii_case("Triggers") || x.len == y.len)
    };
    for o in ops {
        let (Some("DeleteTask"), Some(Target::Task { path })) = (o.kind.as_deref(), o.target.as_ref()) else {
            continue;
        };
        let tree = task_tree(path);
        if !(a.has_key(&tree) && b.has_key(&tree)) {
            continue;
        }
        for n in &tree_names {
            if let (Some(x), Some(y)) = (a.value(&tree, n), b.value(&tree, n))
                && regen_ok(n, x, y)
            {
                out.insert(('~', 'V', canon::fold(&tree), n.to_lowercase()));
            }
        }
        let (Some(old), Some(new)) = (id_of(a, &tree), id_of(b, &tree)) else {
            warnings.push(format!("task {path}: re-registered, but its TaskCache Id is unreadable before or after"));
            continue;
        };
        // The task file (R2a S12): Task Scheduler writes it again on every registration, and the
        // spike shows it differing while the XML and SDDL are equal. Excused exactly, and only when the
        // run acted on the task (the op has an intent), the TaskCache Id changed (a registration
        // happened) and the file stayed a plain file with the same attributes. Its content is vouched
        // for by fidelity (XML and SDDL), not here.
        if o.j.kind.is_some() && !old.eq_ignore_ascii_case(&new) {
            let file = task_file(path);
            if let (Some(x), Some(y)) = (a.path(&file), b.path(&file))
                && !x.dir
                && !y.dir
                && x.attrs == y.attrs
                && x.reparse == 0
                && y.reparse == 0
            {
                out.insert(('~', 'F', canon::fold(&file), String::new()));
            }
        }
        let tasks = |id: &str| format!("{TASKCACHE}\\Tasks\\{id}");
        if old.eq_ignore_ascii_case(&new) {
            for n in &task_names {
                if let (Some(x), Some(y)) = (a.value(&tasks(&old), n), b.value(&tasks(&old), n))
                    && regen_ok(n, x, y)
                {
                    out.insert(('~', 'V', canon::fold(&tasks(&old)), n.to_lowercase()));
                }
            }
            continue;
        }
        // A new Id: the definition key moved; it must hold the same values apart from the regenerated ones.
        let (Some(ka), Some(kb)) = (a.key(&tasks(&old)), b.key(&tasks(&new))) else {
            continue;
        };
        if a.has_key(&tasks(&new)) || b.has_key(&tasks(&old)) {
            continue;
        }
        let same = ka.values.len() == kb.values.len()
            && ka.values.iter().all(|x| match kb.value(&x.name) {
                Some(y) if listed(&task_names, &x.name) => regen_ok(&x.name, x, y),
                Some(y) => (x.typ, x.len, x.hash) == (y.typ, y.len, y.hash),
                None => false,
            });
        if !same {
            continue;
        }
        let mut pair = |ko: String, kn: String, vo: &[crate::snap::ValRec], vn: &[crate::snap::ValRec]| {
            out.insert(('-', 'K', canon::fold(&ko), String::new()));
            out.insert(('+', 'K', canon::fold(&kn), String::new()));
            for v in vo {
                out.insert(('-', 'V', canon::fold(&ko), v.name.to_lowercase()));
            }
            for v in vn {
                out.insert(('+', 'V', canon::fold(&kn), v.name.to_lowercase()));
            }
        };
        pair(tasks(&old), tasks(&new), &ka.values, &kb.values);
        for cat in TASKCACHE_ID_KEYS.iter().filter(|k| **k != "Tasks") {
            let (ko, kn) = (format!("{TASKCACHE}\\{cat}\\{old}"), format!("{TASKCACHE}\\{cat}\\{new}"));
            if let (Some(x), Some(y)) = (a.key(&ko), b.key(&kn))
                && !b.has_key(&ko)
                && !a.has_key(&kn)
                && x.values.len() == y.values.len()
                && x.values
                    .iter()
                    .all(|v| y.value(&v.name).is_some_and(|w| (v.typ, v.len, v.hash) == (w.typ, w.len, w.hash)))
            {
                pair(ko, kn, &x.values, &y.values);
            }
        }
    }
    out
}

fn is_purge_q(p: &str) -> bool {
    let b = p.as_bytes();
    if b.len() < 11 || !b[0].is_ascii_alphabetic() || &b[1..3] != b":\\" {
        return false;
    }
    let rest = &p[3..];
    rest.len() >= 8 && rest[..8].eq_ignore_ascii_case(".purge-q") && (rest.len() == 8 || rest.as_bytes()[8] == b'\\')
}

/// The engine's Restart Manager session state: a key or value at or under
/// `HKU\<sid>\Software\Microsoft\RestartManager` (any user hive). `RmStartSession` writes it during the lock
/// query; it is an allowed side effect of the engine, not ambient churn (RIG.md §11.8).
fn is_engine_rm(c: &Change) -> bool {
    if !matches!(c.rec, 'K' | 'V') {
        return false;
    }
    let s: Vec<&str> = c.path.split('\\').collect();
    s.len() >= 5
        && (s[0].eq_ignore_ascii_case("HKU") || s[0].eq_ignore_ascii_case("HKEY_USERS"))
        && !s[1].is_empty()
        && s[2].eq_ignore_ascii_case("Software")
        && s[3].eq_ignore_ascii_case("Microsoft")
        && s[4].eq_ignore_ascii_case("RestartManager")
}

/// The Volume Shadow Copy service's diagnostics, written when the engine creates its restore point during the
/// exec: a key or value at or under `HKLM\SYSTEM\<CurrentControlSet|ControlSetNNN>\Services\VSS\Diag` that was
/// changed (`~`) or added. A removal (`-`) is never covered. No null run creates a restore point, so this cannot
/// come from the ambient set (RIG.md §11.8).
fn is_engine_rp(c: &Change) -> bool {
    if !matches!(c.rec, 'K' | 'V') || c.op == '-' {
        return false;
    }
    let s: Vec<&str> = c.path.split('\\').collect();
    s.len() >= 6
        && (s[0].eq_ignore_ascii_case("HKLM") || s[0].eq_ignore_ascii_case("HKEY_LOCAL_MACHINE"))
        && s[1].eq_ignore_ascii_case("SYSTEM")
        && (s[2].eq_ignore_ascii_case("CurrentControlSet")
            || (s[2].len() == 13
                && s[2][..10].eq_ignore_ascii_case("ControlSet")
                && s[2][10..].bytes().all(|b| b.is_ascii_digit())))
        && s[3].eq_ignore_ascii_case("Services")
        && s[4].eq_ignore_ascii_case("VSS")
        && s[5].eq_ignore_ascii_case("Diag")
}

/// The broker's image path as the Background Activity Moderator names it (a `\Device\HarddiskVolumeN` prefix):
/// a bam value name must end with this.
const BROKER_BAM_SUFFIX: &str = "\\Program Files\\Purge\\purge-broker.exe";
/// The broker's image path as the Program Compatibility Assistant names it (the value name, exactly).
const BROKER_EXE: &str = "C:\\Program Files\\Purge\\purge-broker.exe";
/// The Program Compatibility Assistant's store key below `HKU\<sid>`.
const PCA_STORE: [&str; 7] =
    ["Software", "Microsoft", "Windows NT", "CurrentVersion", "AppCompatFlags", "Compatibility Assistant", "Store"];

/// What Windows records when purge-broker.exe exits: a completed execute ends the broker inside the gate's exec
/// window (`ExitReason::CompletedChange`, bins/purge-broker/src/lifetime.rs), a declined consent does not, so a
/// null run of the e2e flow never sees these and they cannot come from the ambient set (RIG.md §17.1). Values
/// only, changed (`~`) or added (`+`), never a removal:
/// - `HKLM\SYSTEM\<control set>\Services\bam\State\UserSettings\<sid>`, a value whose name ends with
///   `\Program Files\Purge\purge-broker.exe` (bam's per-user last-run record, named by the device path);
/// - `HKU\<sid>\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store`, the
///   value named exactly `C:\Program Files\Purge\purge-broker.exe` (the Program Compatibility Assistant's record).
///
/// Any other image name stays collateral; the keys' LastWriteTime / value count are left to the parent rule.
fn is_broker_exit(c: &Change) -> bool {
    if c.rec != 'V' || !matches!(c.op, '~' | '+') {
        return false;
    }
    let Some(name) = c.name.as_deref() else { return false };
    let is_sid = |s: &str| {
        s.len() > 4
            && s.is_char_boundary(4)
            && s[..4].eq_ignore_ascii_case("S-1-")
            && s[4..].bytes().all(|b| b.is_ascii_digit() || b == b'-')
    };
    // The bam name is the NT device path of the image: `\Device\HarddiskVolume<n>` and then the path on the volume.
    let bam_prefix_ok = |p: &str| {
        const DEV: &str = r"\Device\HarddiskVolume";
        p.len() > DEV.len()
            && p.is_char_boundary(DEV.len())
            && p[..DEV.len()].eq_ignore_ascii_case(DEV)
            && p[DEV.len()..].bytes().all(|b| b.is_ascii_digit())
    };
    if let Some(r) = system_cs_rest(&c.path) {
        let n = BROKER_BAM_SUFFIX.len();
        return r.len() == 5
            && segs_eq(&r[..4], &["Services", "bam", "State", "UserSettings"])
            && is_sid(r[4])
            && name.len() > n
            && name.is_char_boundary(name.len() - n)
            && name[name.len() - n..].eq_ignore_ascii_case(BROKER_BAM_SUFFIX)
            && bam_prefix_ok(&name[..name.len() - n]);
    }
    let s: Vec<&str> = c.path.split('\\').collect();
    s.len() == 9
        && (s[0].eq_ignore_ascii_case("HKU") || s[0].eq_ignore_ascii_case("HKEY_USERS"))
        && is_sid(s[1])
        && segs_eq(&s[2..], &PCA_STORE)
        && name.eq_ignore_ascii_case(BROKER_EXE)
}

/// Windows' prefetch bookkeeping (DECISIONS 2026-11-24, E): a file directly in `<drive>:\Windows\Prefetch` whose
/// name ends in `.pf`, changed (`~`) only in its size and/or LastWriteTime. The prefetcher rewrites the trace of any
/// process that ran in the window (`SVCHOST.EXE-C5EEC15E.pf` in e2e-final3 git), whatever its 8-hex-digit hash;
/// Purge's file ops only ever produce removals, so an addition, a removal, a kind / attribute / reparse change or a
/// file elsewhere is never covered and stays collateral.
fn is_windows_prefetch(c: &Change) -> bool {
    if c.rec != 'F' || c.op != '~' || c.changes.is_empty() {
        return false;
    }
    if !c.changes.iter().all(|x| x.starts_with("size ") || x.starts_with("mtime ")) {
        return false;
    }
    let s: Vec<&str> = c.path.split('\\').collect();
    let drive = |d: &str| d.len() == 2 && d.as_bytes()[0].is_ascii_alphabetic() && d.as_bytes()[1] == b':';
    s.len() == 4
        && drive(s[0])
        && s[1].eq_ignore_ascii_case("Windows")
        && s[2].eq_ignore_ascii_case("Prefetch")
        && s[3].len() > 3
        && s[3].is_char_boundary(s[3].len() - 3)
        && s[3][s[3].len() - 3..].eq_ignore_ascii_case(".pf")
}

/// `HKLM\SYSTEM\<CurrentControlSet|ControlSetNNN>\<rest...>`: the segments after the control set, or None.
fn system_cs_rest(path: &str) -> Option<Vec<&str>> {
    let s: Vec<&str> = path.split('\\').collect();
    let ok = s.len() >= 3
        && (s[0].eq_ignore_ascii_case("HKLM") || s[0].eq_ignore_ascii_case("HKEY_LOCAL_MACHINE"))
        && s[1].eq_ignore_ascii_case("SYSTEM")
        && (s[2].eq_ignore_ascii_case("CurrentControlSet")
            || (s[2].len() == 13
                && s[2].is_char_boundary(10)
                && s[2][..10].eq_ignore_ascii_case("ControlSet")
                && s[2][10..].bytes().all(|b| b.is_ascii_digit())));
    ok.then(|| s[3..].to_vec())
}

/// Does `rest` (path segments) equal `want`, case-insensitively?
fn segs_eq(rest: &[&str], want: &[&str]) -> bool {
    rest.len() == want.len() && rest.iter().zip(want).all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// The Volume Snapshot device class (volsnap's device instances, `HarddiskVolumeSnapshot<n>`).
const VOLSNAP_CLASS: &str = "{533c5b84-ec70-11d2-9505-00c04f79deaf}";
/// The "no container" device container, which holds the volume snapshot devices.
const NULL_CONTAINER: &str = "{00000000-0000-0000-FFFF-FFFFFFFFFFFF}";
const HARDDISK_VOLUME_SNAPSHOT: &str = "STORAGE\\VolumeSnapshot\\HarddiskVolumeSnapshot";
const WMI_TRACING: &str = "HKLM\\SOFTWARE\\Microsoft\\Wbem\\Tracing\\Providers";
/// The System Restore WMI provider (the engine creates its restore point through it).
const SR_PROVIDER: &str = "SystemRestoreProv @ root/default";
/// The Windows Firewall WMI provider (the engine deletes a firewall rule through it).
const FW_PROVIDER: &str = "wfascim @ ROOT/StandardCimv2";
const NT_CURRENT: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
const WFPDIAG: &str = "C:\\ProgramData\\Microsoft\\Windows\\wfp\\wfpdiag.etl";

/// A WMI provider's tracing key `Wbem\Tracing\Providers\<provider>` (exactly): added, or changed in its
/// LastWriteTime / value count only; or a value added to it whose name is a number (the provider's load time, a
/// FILETIME). Nothing else, and never a removal.
fn is_wmi_tracing(c: &Change, provider: &str) -> bool {
    if !canon::ci_eq(&c.path, &format!("{WMI_TRACING}\\{provider}")) {
        return false;
    }
    match (c.op, c.rec) {
        ('+', 'K') => true,
        ('~', 'K') => only_changes(c, &["lwt ", "n_values "]),
        ('+', 'V') => c.name.as_deref().is_some_and(all_digits),
        _ => false,
    }
}

/// What creating a restore point writes besides `VSS\Diag` (the M1b executor runs of 2026-11-19, absent from the
/// M2 runs whose restore point was `NotRequested`). Applied only when the exec report's restore point is `Created`
/// (`check`); additions and changes only, a removal (`-`) is never covered:
/// - a new volume snapshot device instance: the key `Control\Class\{533c5b84-...}\<4 digits>` and its values, added;
/// - its container entry: the value `STORAGE\VolumeSnapshot\HarddiskVolumeSnapshot<n>` added to
///   `Control\DeviceContainers\{00000000-0000-0000-FFFF-FFFFFFFFFFFF}\BaseContainers\{same}`;
/// - the System Restore WMI provider's tracing key (`is_wmi_tracing`, `SystemRestoreProv @ root/default`);
/// - `Windows NT\CurrentVersion\SPP|LastIndex` and `Windows NT\CurrentVersion\SystemRestore|LastIndex`, changed;
/// - `Services\DsmSvc\State|SessionNumber`, changed (Device Setup Manager reacting to the new device);
/// - `<drive>:\System Volume Information` (the directory itself), its mtime only changed;
/// - a loaded user hive's transaction log (`is_user_hive_log`), its size / mtime only changed (never removed).
///
/// The keys around them (LastWriteTime, value / subkey count) are left to the parent rule.
fn is_engine_rp_created(c: &Change) -> bool {
    if c.op == '-' {
        return false;
    }
    if let Some(r) = system_cs_rest(&c.path) {
        if c.op == '+'
            && matches!(c.rec, 'K' | 'V')
            && r.len() == 4
            && segs_eq(&r[..3], &["Control", "Class", VOLSNAP_CLASS])
            && r[3].len() == 4
            && all_digits(r[3])
        {
            return true;
        }
        if c.op == '+'
            && c.rec == 'V'
            && segs_eq(&r, &["Control", "DeviceContainers", NULL_CONTAINER, "BaseContainers", NULL_CONTAINER])
        {
            let p = HARDDISK_VOLUME_SNAPSHOT;
            return c.name.as_deref().is_some_and(|n| {
                n.len() > p.len()
                    && n.is_char_boundary(p.len())
                    && n[..p.len()].eq_ignore_ascii_case(p)
                    && all_digits(&n[p.len()..])
            });
        }
        return c.op == '~'
            && c.rec == 'V'
            && segs_eq(&r, &["Services", "DsmSvc", "State"])
            && c.name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case("SessionNumber"));
    }
    if is_wmi_tracing(c, SR_PROVIDER) {
        return true;
    }
    if c.op == '~' && c.rec == 'V' {
        return c.name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case("LastIndex"))
            && (canon::ci_eq(&c.path, &format!("{NT_CURRENT}\\SPP"))
                || canon::ci_eq(&c.path, &format!("{NT_CURRENT}\\SystemRestore")));
    }
    if c.op == '~' && c.rec == 'D' && only_changes(c, &["mtime "]) {
        let b = c.path.as_bytes();
        return b.len() == 28
            && b[0].is_ascii_alphabetic()
            && c.path[1..].eq_ignore_ascii_case(":\\System Volume Information");
    }
    c.op == '~' && c.rec == 'F' && only_changes(c, &["size ", "mtime "]) && is_user_hive_log(&c.path)
}

/// A loaded user hive's transaction log: `<drive>:\Users\<profile>\ntuser.dat.LOG1|LOG2` or
/// `<drive>:\Users\<profile>\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1|LOG2` (one profile segment). The
/// restore point's VSS registry writer flushes the loaded hives, which rotates and truncates these logs (user ruling
/// 2026-11-20 after the R8 S1 replay: they changed in both failed runs and in none of the 12 null runs).
fn is_user_hive_log(path: &str) -> bool {
    let s: Vec<&str> = path.split('\\').collect();
    let drive = |d: &str| d.len() == 2 && d.as_bytes()[0].is_ascii_alphabetic() && d.as_bytes()[1] == b':';
    let log = |f: &str, base: &str| {
        f.len() == base.len() + 5
            && f.is_char_boundary(base.len())
            && f[..base.len()].eq_ignore_ascii_case(base)
            && (f[base.len()..].eq_ignore_ascii_case(".LOG1") || f[base.len()..].eq_ignore_ascii_case(".LOG2"))
    };
    if s.len() < 4 || !drive(s[0]) || !s[1].eq_ignore_ascii_case("Users") || s[2].is_empty() {
        return false;
    }
    match s.len() {
        4 => log(s[3], "ntuser.dat"),
        8 => segs_eq(&s[3..7], &["AppData", "Local", "Microsoft", "Windows"]) && log(s[7], "UsrClass.dat"),
        _ => false,
    }
}

/// What deleting a firewall rule writes (the M1b executor runs of 2026-11-19). Applied only when the journal has a
/// `DeleteFirewallRule` op whose effective outcome is `Done` (`check`); additions and changes only:
/// - the firewall WMI provider's tracing key (`is_wmi_tracing`, `wfascim @ ROOT/StandardCimv2`);
/// - `Services\SharedAccess\Epoch|Epoch`, changed (the firewall policy store's change counter);
/// - `C:\ProgramData\Microsoft\Windows\wfp\wfpdiag.etl`, changed (the WFP diagnostics trace).
fn is_engine_fw_delete(c: &Change) -> bool {
    if c.op == '-' {
        return false;
    }
    if let Some(r) = system_cs_rest(&c.path) {
        return c.op == '~'
            && c.rec == 'V'
            && segs_eq(&r, &["Services", "SharedAccess", "Epoch"])
            && c.name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case("Epoch"));
    }
    if is_wmi_tracing(c, FW_PROVIDER) {
        return true;
    }
    c.op == '~' && c.rec == 'F' && canon::ci_eq(&c.path, WFPDIAG)
}

fn row_of(c: &Change) -> DiffRow {
    DiffRow {
        change: format!("{}{}", c.op, c.rec),
        path: c.path.clone(),
        name: c.name.clone(),
        changes: c.changes.clone(),
    }
}

/// The diff record as a target, for the ambient matcher and the rig rules.
fn target_of(c: &Change) -> Target {
    match c.rec {
        'D' | 'F' => Target::Path { path: c.path.clone() },
        'K' => Target::RegKey { path: c.path.clone() },
        _ if c.op == '~' => Target::RegValueChanged {
            path: c.path.clone(),
            name: c.name.clone().unwrap_or_default(),
            before: String::new(),
            after: String::new(),
        },
        _ => Target::RegValue { path: c.path.clone(), name: c.name.clone().unwrap_or_default() },
    }
}

fn only_changes(c: &Change, prefixes: &[&str]) -> bool {
    !c.changes.is_empty() && c.changes.iter().all(|x| prefixes.iter().any(|p| x.starts_with(p)))
}

enum Src {
    Intact,
    Changed(Vec<String>),
    Missing(String),
    Unverified(String),
}

fn canary_snap(c: &Canary, a: &Snap, b: &Snap) -> Src {
    match c.kind.as_str() {
        "file" => {
            let Some(ra) = a.path(&c.path) else {
                return Src::Unverified(if a.captures_path(&c.path) {
                    "snap: absent in the before snapshot".into()
                } else {
                    "snap: not captured by the before snapshot".into()
                });
            };
            let Some(rb) = b.path(&c.path) else {
                return Src::Missing("snap: absent after".into());
            };
            let mut d = Vec::new();
            if ra.dir != rb.dir {
                d.push(format!("snap: kind {}->{}", if ra.dir { "D" } else { "F" }, if rb.dir { "D" } else { "F" }));
            }
            if ra.size != rb.size {
                d.push(format!("snap: size {}->{}", ra.size, rb.size));
            }
            if ra.attrs != rb.attrs {
                d.push(format!("snap: attrs {:x}->{:x}", ra.attrs, rb.attrs));
            }
            if ra.mtime != rb.mtime {
                d.push(format!("snap: mtime {}->{}", ra.mtime, rb.mtime));
            }
            if ra.reparse != rb.reparse || rb.reparse != 0 {
                d.push(format!("snap: reparse {:x}->{:x}", ra.reparse, rb.reparse));
            }
            if d.is_empty() { Src::Intact } else { Src::Changed(d) }
        }
        "regkey" => {
            let Some(ka) = a.key(&c.path) else {
                return Src::Unverified(if a.captures_key(&c.path) {
                    "snap: absent in the before snapshot".into()
                } else {
                    "snap: not captured by the before snapshot".into()
                });
            };
            if !a.values_known(&c.path) {
                return Src::Unverified("snap: values not listed in the before snapshot".into());
            }
            let Some(kb) = b.key(&c.path) else {
                return Src::Missing("snap: key absent after".into());
            };
            if !b.values_known(&c.path) {
                return Src::Unverified("snap: values not listed in the after snapshot".into());
            }
            let m = |k: &crate::snap::KeyRec| -> BTreeMap<String, (u32, u64)> {
                k.values.iter().map(|v| (canon::fold(&v.name), (v.typ, v.hash))).collect()
            };
            let (va, vb) = (m(ka), m(kb));
            let mut d = Vec::new();
            for n in va.keys().chain(vb.keys()).collect::<std::collections::BTreeSet<_>>() {
                match (va.get(n), vb.get(n)) {
                    (Some(x), Some(y)) if x == y => {}
                    (Some(_), None) => d.push(format!("snap: value {n:?} removed")),
                    (None, Some(_)) => d.push(format!("snap: value {n:?} added")),
                    _ => d.push(format!("snap: value {n:?} changed")),
                }
            }
            if d.is_empty() { Src::Intact } else { Src::Changed(d) }
        }
        _ => {
            let name = c.name.as_deref().unwrap_or("");
            let Some(va) = a.value(&c.path, name) else {
                return Src::Unverified(if a.values_known(&c.path) {
                    "snap: absent in the before snapshot".into()
                } else {
                    "snap: not captured by the before snapshot".into()
                });
            };
            let Some(vb) = b.value(&c.path, name) else {
                return Src::Missing("snap: value absent after".into());
            };
            if (va.typ, va.hash) == (vb.typ, vb.hash) {
                Src::Intact
            } else {
                Src::Changed(vec![format!(
                    "snap: type/data {}:{:016x} -> {}:{:016x}",
                    va.typ, va.hash, vb.typ, vb.hash
                )])
            }
        }
    }
}

struct DeepIdx<'a> {
    files: HashMap<String, &'a FileRec>,
    keys: HashMap<String, &'a DeepKey>,
}

impl<'a> DeepIdx<'a> {
    fn new(d: &'a DeepDoc) -> Self {
        DeepIdx {
            files: d.files.iter().map(|f| (canon::fold(&f.path), f)).collect(),
            keys: d.keys.iter().map(|k| (canon::fold(&k.key), k)).collect(),
        }
    }
}

const DEEP_FILE_FIELDS: &[&str] = &[
    "present",
    "is_dir",
    "attributes",
    "size",
    "sha256",
    "streams",
    "links",
    "file_id",
    "volume_serial",
    "reparse_tag",
    "link_target",
    "reparse_sha256",
    "owner",
    "sddl",
    "error",
];

fn field_diffs<T: Serialize>(a: &T, b: &T, fields: &[&str]) -> Vec<String> {
    let (va, vb) = (serde_json::to_value(a).unwrap_or(Value::Null), serde_json::to_value(b).unwrap_or(Value::Null));
    fields
        .iter()
        .filter(|f| va.get(**f) != vb.get(**f))
        .map(|f| format!("deep: {f} {} -> {}", va.get(*f).unwrap_or(&Value::Null), vb.get(*f).unwrap_or(&Value::Null)))
        .collect()
}

fn deep_values(k: &DeepKey) -> BTreeMap<String, (u32, u32, String)> {
    k.values.iter().map(|v| (canon::fold(&v.name), (v.typ, v.len, v.sha256.clone()))).collect()
}

fn canary_deep(c: &Canary, da: Option<&DeepIdx>, db: &DeepIdx) -> Src {
    let f = canon::fold(&c.path);
    match c.kind.as_str() {
        "file" => {
            let Some(rb) = db.files.get(&f) else {
                return Src::Unverified("deep: not in the after deep snapshot".into());
            };
            if let Some(e) = &rb.error {
                return Src::Unverified(format!("deep: {e}"));
            }
            if !rb.present {
                return Src::Missing("deep: absent after".into());
            }
            let mut d = Vec::new();
            if rb.is_dir == Some(true) {
                d.push("deep: is a directory".to_string());
            }
            if let Some(t) = &rb.reparse_tag {
                d.push(format!("deep: reparse tag {t}"));
            }
            if let Some(want) = &c.sha256
                && rb.sha256.as_deref() != Some(want.as_str())
            {
                d.push(format!("deep: sha256 {} (manifest {want})", rb.sha256.as_deref().unwrap_or("none")));
            }
            if let Some(ra) = da.and_then(|x| x.files.get(&f)) {
                d.extend(field_diffs(*ra, *rb, DEEP_FILE_FIELDS));
            }
            if d.is_empty() { Src::Intact } else { Src::Changed(d) }
        }
        kind => {
            let Some(kb) = db.keys.get(&f) else {
                return Src::Unverified("deep: not in the after deep snapshot".into());
            };
            if let Some(e) = &kb.error {
                return Src::Unverified(format!("deep: {e}"));
            }
            if !kb.present {
                return Src::Missing("deep: key absent after".into());
            }
            let Some(ka) = da.and_then(|x| x.keys.get(&f)) else {
                return Src::Unverified("deep: values need the before deep snapshot".into());
            };
            let mut d = Vec::new();
            if kb.is_link == Some(true) {
                d.push("deep: key is a registry link".into());
            }
            let (va, vb) = (deep_values(ka), deep_values(kb));
            if kind == "regkey" {
                if va != vb {
                    d.push("deep: values differ".into());
                }
                d.extend(field_diffs(*ka, *kb, &["sddl", "is_link", "link_target", "class"]));
            } else {
                let n = canon::fold(c.name.as_deref().unwrap_or(""));
                match (va.get(&n), vb.get(&n)) {
                    (_, None) => return Src::Missing("deep: value absent after".into()),
                    (Some(x), Some(y)) if x == y => {}
                    (None, Some(_)) => return Src::Unverified("deep: value absent before".into()),
                    _ => d.push("deep: value type/data differ".into()),
                }
            }
            if d.is_empty() { Src::Intact } else { Src::Changed(d) }
        }
    }
}

/// A trap item's build condition: the build record's attribute / reparse-tag objects at or under the item's target
/// all set (`met`), one not set (`unmet`), none recorded (`unknown`); `None` when the item has no condition.
fn condition_status(t: &Trap, it: &TrapItem) -> Option<&'static str> {
    it.condition.as_ref().map(|_| {
        let rel: Vec<&BuildObj> = t
            .build_objects
            .iter()
            .filter(|o| {
                matches!(o.k.as_str(), "attrs" | "cloud-tag") && canon::is_under_or_eq(&o.path, it.target.path())
            })
            .collect();
        if rel.is_empty() {
            "unknown"
        } else if rel.iter().all(|o| o.ok) {
            "met"
        } else {
            "unmet"
        }
    })
}

/// FILETIME of a snapshot header time (`YYYY-MM-DDTHH:MM:SS`, UTC, optional fraction and `Z`); `None` if unreadable.
fn header_filetime(iso: &str) -> Option<u64> {
    let b = iso.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| iso.get(r)?.parse::<i64>().ok();
    let (y, m, d, hh, mm, ss) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    // days from civil (H. Hinnant)
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let unix = days * 86400 + hh * 3600 + mm * 60 + ss;
    u64::try_from((unix + 11_644_473_600) * 10_000_000).ok()
}

/// A directory whose only change is its LastWriteTime, from one time to another that both lie before the before
/// snapshot was taken: NTFS updates the copy of a directory's times in its parent's index lazily, and the snapshot
/// reads that copy, so a change made before the run can show up between two snapshots. Nothing the run did can
/// carry a time earlier than the before snapshot.
fn stale_dir_time(c: &Change, before_ft: Option<u64>) -> bool {
    let Some(t0) = before_ft else { return false };
    if c.rec != 'D' || c.op != '~' || c.changes.len() != 1 {
        return false;
    }
    let Some(rest) = c.changes[0].strip_prefix("mtime ") else { return false };
    let Some((x, y)) = rest.split_once("->") else { return false };
    matches!((x.trim().parse::<u64>(), y.trim().parse::<u64>()), (Ok(x), Ok(y)) if x < t0 && y < t0)
}

/// Effect of one op in the snapshots.
fn effect(o: &OpT, all: &[OpT], a: &Snap, b: &Snap, helper_dirs: &[String]) -> (String, String) {
    let ok = |d: &str| ("ok".to_string(), d.to_string());
    let unv = |d: &str| ("unverified".to_string(), d.to_string());
    let (Some(kind), Some(t)) = (o.kind.as_deref(), o.target.as_ref()) else {
        // No ExecOp known: neither journal intent nor report entry.
        return unv("op kind unknown");
    };
    let outcome = o.j.outcome.as_deref();
    // (present before, present after, verifiable, same data) of the target object.
    let (pa, pb, verifiable, same) = match t {
        Target::Path { path } => {
            let (ra, rb) = (a.path(path), b.path(path));
            let same = match (ra, rb) {
                (Some(x), Some(y)) => {
                    x.dir == y.dir
                        && x.attrs == y.attrs
                        && x.reparse == y.reparse
                        && (x.dir || (x.size, x.mtime) == (y.size, y.mtime))
                }
                _ => false,
            };
            (ra.is_some(), rb.is_some(), ra.is_some() || a.captures_path(path), same)
        }
        Target::RegKey { path } => {
            let (pa, pb) = (a.has_key(path), b.has_key(path));
            (pa, pb, pa || a.captures_key(path), pa && pb)
        }
        Target::RegValue { path, name } | Target::RegMultiSzSegment { path, name, .. } => {
            let (va, vb) = (a.value(path, name), b.value(path, name));
            let same = matches!((va, vb), (Some(x), Some(y)) if (x.typ, x.hash) == (y.typ, y.hash));
            (va.is_some(), vb.is_some(), va.is_some() || a.values_known(path), same)
        }
        Target::Service { name } => {
            let key = format!("{SERVICES}\\{name}");
            let (pa, pb) = (a.has_key(&key), b.has_key(&key));
            if outcome == Some("PendingDelete") {
                if !pa {
                    return unv("absent in the before snapshot");
                }
                let flagged = b.value(&key, "DeleteFlag").is_some_and(|v| v.preview == "1");
                return match (pb, flagged) {
                    (false, _) => ok("gone after"),
                    (true, true) => ok("marked for deletion (DeleteFlag 1)"),
                    (true, false) => ("missing".into(), "PendingDelete, but the key has no DeleteFlag 1".into()),
                };
            }
            let same = pa && pb && a.key(&key).map(|k| &k.values) == b.key(&key).map(|k| &k.values);
            (pa, pb, pa || a.captures_key(&key), same)
        }
        Target::Task { path } => {
            let (file, tree) = (task_file(path), task_tree(path));
            let (fa, fb) = (a.path(&file), b.path(&file));
            let (pa, pb) = (fa.is_some() || a.has_key(&tree), fb.is_some() || b.has_key(&tree));
            let same = matches!((fa, fb), (Some(x), Some(y)) if (x.size, x.mtime) == (y.size, y.mtime))
                && a.value(&tree, "Id").map(|v| v.hash) == b.value(&tree, "Id").map(|v| v.hash);
            (pa, pb, pa || (a.captures_path(&file) && a.captures_key(&tree)), same)
        }
        Target::FirewallRule { id } => {
            let (va, vb) = (a.value(FW_RULES, id), b.value(FW_RULES, id));
            let same = matches!((va, vb), (Some(x), Some(y)) if (x.typ, x.hash) == (y.typ, y.hash));
            (va.is_some(), vb.is_some(), va.is_some() || a.values_known(FW_RULES), same)
        }
        Target::AppxPackage { .. } => return unv("packages are not in snapshots"),
        _ => return unv("target kind not checked"),
    };
    if !verifiable {
        return unv("not captured by the before snapshot");
    }
    // A removed op whose target covers this one (nested items).
    let taken_by = || {
        all.iter()
            .filter(|x| x.j.op != o.j.op && x.removed())
            .find(|x| {
                let probe = Change {
                    op: '-',
                    rec: match t {
                        Target::Path { .. } => 'F',
                        Target::RegKey { .. } => 'K',
                        _ => 'V',
                    },
                    path: t.path().to_string(),
                    name: t.value_name().map(str::to_string),
                    changes: Vec::new(),
                };
                x.covers(&probe)
            })
            .map(|x| x.j.op)
    };
    match outcome {
        Some("Done") => {
            if !pa {
                return unv("absent in the before snapshot");
            }
            if kind == "EditSegment" {
                return match (pb, same) {
                    (true, false) => ok("value data changed"),
                    (true, true) => ("missing".into(), "value data unchanged".into()),
                    (false, _) => ("changed".into(), "the edited value is gone".into()),
                };
            }
            // A race helper put a junction where the directory was: the engine moved the original object through
            // its handle (an accepted race outcome); what stands at the path now is the helper's link.
            if pb
                && let Target::Path { path } = t
                && helper_dirs.iter().any(|h| canon::ci_eq(path, h))
                && let (Some(x), Some(y)) = (a.path(path), b.path(path))
                && x.reparse == 0
                && y.reparse != 0
            {
                return ok("moved through the handle; the race helper's link stands at the path after");
            }
            if pb { ("missing".into(), "still present after".into()) } else { ok("gone after") }
        }
        Some("Vanished") => match (pa, pb) {
            (_, true) => ok("vanished per journal, present after"),
            (true, false) => match taken_by() {
                Some(n) => ok(&format!("removed with op {n}")),
                None => ok("present before, gone after (not by this op)"),
            },
            (false, false) => ok("absent before and after"),
        },
        _ => {
            if pa == pb && (!pa || same) {
                return ok("unchanged");
            }
            if pa
                && !pb
                && let Some(n) = taken_by()
            {
                return ok(&format!("removed with op {n}"));
            }
            let what = match (pa, pb) {
                (true, false) => "gone after",
                (false, true) => "appeared after",
                _ => "changed",
            };
            ("changed".into(), format!("{what}, outcome {}", outcome.unwrap_or("none")))
        }
    }
}

pub fn check(cx: &Ctx) -> Result<ExecdiffReport> {
    let (j, rep) = (cx.journal, cx.report);
    let h = &j.header;
    if h.session != rep.session {
        bail!("journal session {} is not the report's {}", h.session, rep.session);
    }
    if h.plan_hash != rep.plan_hash || h.selection_hash != rep.selection_hash {
        bail!("journal and report name different plan or selection hashes");
    }
    let mut warnings: Vec<String> = j.warnings.iter().map(|w| format!("journal: {w}")).collect();
    let mut incons: Vec<String> = Vec::new();
    if j.undo_records > 0 {
        warnings.push(format!("journal holds {} undo records: execdiff checks an exec run", j.undo_records));
    }

    // Report vs journal.
    let by_op: HashMap<u32, &ReportItem> = rep.items.iter().map(|i| (i.op, i)).collect();
    for i in &rep.items {
        match j.op(i.op) {
            None => incons.push(format!("report item {} (op {}) is not in the journal", i.item, i.op)),
            Some(o) => {
                if o.item != i.item {
                    incons.push(format!("op {}: journal item {}, report item {}", i.op, o.item, i.item));
                }
                if o.reconciled.is_empty()
                    && let Some(d) = &o.done
                    && d != &i.outcome
                {
                    incons.push(format!(
                        "op {}: journal outcome {}, report {}",
                        i.op,
                        d.summary(),
                        i.outcome.summary()
                    ));
                }
                match (&o.exec_op, &i.exec_op) {
                    (Some(e), Some(r)) if e != r => {
                        incons.push(format!("op {}: journal exec_op {}, report {}", i.op, e.name(), r.name()));
                    }
                    (Some(e), None) => {
                        incons.push(format!("op {}: journal exec_op {}, report none", i.op, e.name()));
                    }
                    _ => {}
                }
            }
        }
    }
    for o in &j.ops {
        if !by_op.contains_key(&o.op) {
            incons.push(format!("journal op {} (item {}) is not in the report", o.op, o.item));
        }
    }
    let mut tally = OutcomeCounts::default();
    for i in &rep.items {
        tally.record(&i.outcome);
    }
    if tally != rep.counts {
        incons.push(format!("report counts {:?} differ from its items {:?}", rep.counts, tally));
    }
    let state_ok = match rep.state.as_str() {
        "Committed" => j.committed,
        "Aborted" => j.aborted.is_some(),
        _ => true,
    };
    if !state_ok {
        incons.push(format!("report state {} but journal {}", rep.state, j.state()));
    }

    // Ops.
    let ops: Vec<OpT> = j
        .ops
        .iter()
        .map(|o| {
            let ri = by_op.get(&o.op);
            let report_op = ri.and_then(|i| i.exec_op.as_ref());
            let kind = o.kind.clone().or_else(|| report_op.map(|e| e.name().to_string()));
            let target = o
                .exec_op
                .as_ref()
                .map(ExecOp::target)
                .or_else(|| report_op.map(ExecOp::target))
                .or_else(|| o.target.clone())
                .map(|t| t.canonical(cx.sid));
            let task_id = match &target {
                Some(Target::Task { path }) => {
                    cx.a.value(&task_tree(path), "Id")
                        .map(|v| v.preview.trim().to_string())
                        .filter(|id| is_braced_guid(id))
                }
                _ => None,
            };
            OpT { j: o, kind, target, task_id }
        })
        .collect();
    let rereg = task_reregistrations(&ops, cx.a, cx.b, crate::fidelity::spike_rules(), &mut warnings);
    let pending = j.ops.iter().any(|o| {
        o.outcome.as_deref() == Some("PendingReboot")
            || o.done.as_ref().is_some_and(|d| d.name() == "PendingReboot")
            || !o.reconciled.is_empty()
    });
    let mut stores: Vec<String> = vec![PURGE_STORE.to_string()];
    stores.extend(h.volumes.iter().map(|v| canon::canon_path(&v.quarantine)));
    let rig = RigRules::new(&[cx.a, cx.b]);
    let scored: Vec<String> = if cx.groups.is_empty() { vec!["main".into()] } else { cx.groups.to_vec() };
    let helper_dirs: Vec<String> = cx
        .manifests
        .iter()
        .flat_map(|m| m.traps.iter())
        .filter(|t| t.items.iter().any(|i| scored.contains(&i.group)))
        .filter_map(|t| t.helper_dir.clone())
        .collect();

    let before_ft = header_filetime(&cx.a.header.time);
    if before_ft.is_none() {
        warnings.push(format!("before snapshot time {:?} unreadable: no stale-dir-time rule", cx.a.header.time));
    }

    // The engine's side effects that depend on what this run did (RIG.md §12.8): the restore point the report
    // says it created; a firewall rule the journal says it deleted.
    let rp_created = rep.restore_point.kind == "Created";
    let fw_deleted =
        ops.iter().any(|o| o.kind.as_deref() == Some("DeleteFirewallRule") && o.j.outcome.as_deref() == Some("Done"));

    // Classify diff records.
    let d = diff::diff(cx.a, cx.b);
    let mut counts = Counts { diff_records: d.len() as u64, ..Default::default() };
    let mut auth: Vec<Option<&'static str>> = Vec::with_capacity(d.len());
    for c in &d {
        let t = target_of(c);
        let a: Option<&'static str> = if ops.iter().any(|o| o.removed() && o.covers(c)) {
            Some("op")
        } else if ops.iter().any(|o| o.covers_pending_delete(c)) {
            Some("pending-delete")
        } else if rereg.contains(&change_id(c)) {
            Some("task-reregistered")
        } else if matches!(c.rec, 'D' | 'F')
            && (stores.iter().any(|s| canon::is_under_or_eq(&c.path, s)) || is_purge_q(&c.path))
        {
            Some("store")
        } else if rig.check(&t.canon_string()).is_some() {
            Some("rig")
        } else if pending
            && c.rec == 'V'
            && canon::ci_eq(&c.path, SESSION_MANAGER)
            && canon::ci_eq(c.name.as_deref().unwrap_or(""), PFRO)
        {
            Some("pending-rename")
        } else if is_engine_rm(c) {
            Some("engine-rm")
        } else if is_engine_rp(c) || (rp_created && is_engine_rp_created(c)) {
            Some("engine-rp")
        } else if fw_deleted && is_engine_fw_delete(c) {
            Some("engine-fw")
        } else if is_broker_exit(c) {
            Some("broker-exit")
        } else if is_windows_prefetch(c) {
            Some("windows-prefetch")
        } else if cx.ambient.and_then(|m| m.matches_change(c, &t)).is_some() {
            Some("ambient")
        } else if stale_dir_time(c, before_ft) {
            Some("stale-dir-time")
        } else {
            None
        };
        auth.push(a);
    }
    // Parents of authorised additions and removals.
    let mut dir_parents: HashSet<String> = HashSet::new();
    let mut key_parents: HashSet<String> = HashSet::new();
    for (c, a) in d.iter().zip(&auth) {
        if a.is_none() {
            continue;
        }
        match (c.rec, c.op) {
            ('D' | 'F', '+' | '-') => {
                if let Some(p) = canon::parent(&c.path) {
                    dir_parents.insert(canon::fold(p));
                }
            }
            ('K', '+' | '-') => {
                if let Some(p) = canon::parent(&c.path) {
                    key_parents.insert(canon::fold(p));
                }
            }
            ('V', _) => {
                key_parents.insert(canon::fold(&c.path));
            }
            _ => {}
        }
    }
    // Race helpers of the scored groups: the swapped directory (now a junction) and its parent's LastWriteTime.
    for (c, a) in d.iter().zip(auth.iter_mut()) {
        if matches!(c.rec, 'D' | 'F') && helper_dirs.iter().any(|h| canon::ci_eq(&c.path, h)) {
            if a.is_none() {
                *a = Some("helper");
            }
            if let Some(p) = canon::parent(&c.path) {
                dir_parents.insert(canon::fold(p));
            }
        }
    }
    let mut collateral = Vec::new();
    let mut unexplained = Vec::new();
    for (c, a) in d.iter().zip(auth.iter_mut()) {
        if a.is_none() && c.op == '~' {
            let parent = match c.rec {
                'D' => only_changes(c, &["mtime "]) && dir_parents.contains(&canon::fold(&c.path)),
                'K' => {
                    only_changes(c, &["lwt ", "n_values ", "n_subkeys "]) && key_parents.contains(&canon::fold(&c.path))
                }
                _ => false,
            };
            if parent {
                *a = Some("parent");
            }
        }
        match a {
            Some(r) => *counts.authorised.entry(r.to_string()).or_default() += 1,
            None if c.op == '+' => unexplained.push(row_of(c)),
            None => collateral.push(row_of(c)),
        }
    }

    // Effects.
    let mut effects = Vec::new();
    for o in &ops {
        let (verdict, detail) = effect(o, &ops, cx.a, cx.b, &helper_dirs);
        match verdict.as_str() {
            "missing" => counts.missing_effects += 1,
            "changed" => counts.changed_not_done += 1,
            "unverified" => counts.unverified_effects += 1,
            _ => {}
        }
        effects.push(EffectRow {
            op: o.j.op,
            item: o.j.item.clone(),
            kind: o.kind.clone(),
            target: o.target.as_ref().map(Target::canon_string),
            outcome: o.j.outcome.clone(),
            verdict,
            detail,
        });
    }

    // Canaries.
    let da = cx.deep_a.map(DeepIdx::new);
    let db = cx.deep_b.map(DeepIdx::new);
    // Targets of trap items whose build condition is unmet (e.g. a placeholder attribute Windows would not set):
    // the object there is an ordinary file, so a canary on it is not a protected object and is not scored.
    let unmet: Vec<(String, String)> = cx
        .manifests
        .iter()
        .flat_map(|m| m.traps.iter())
        .flat_map(|t| t.items.iter().map(move |it| (t, it)))
        .filter(|(t, it)| condition_status(t, it) == Some("unmet"))
        .map(|(_, it)| (it.id.clone(), canon::canon_path(it.target.path())))
        .collect();
    let mut canaries = Vec::new();
    for m in cx.manifests {
        for c in &m.canaries {
            if c.kind == "file"
                && let Some((iid, _)) = unmet.iter().find(|(_, p)| canon::is_under_or_eq(&c.path, p))
            {
                canaries.push(CanaryRow {
                    id: c.id.clone(),
                    trap: c.trap.clone(),
                    kind: c.kind.clone(),
                    path: c.path.clone(),
                    name: c.name.clone(),
                    verdict: "not-scored".to_string(),
                    verified_by: Vec::new(),
                    evidence: vec![format!("trap item {iid}: build condition unmet, an ordinary plan item")],
                });
                continue;
            }
            let mut srcs = vec![("snap", canary_snap(c, cx.a, cx.b))];
            if let Some(db) = &db {
                srcs.push(("deep", canary_deep(c, da.as_ref(), db)));
            }
            let mut evidence = Vec::new();
            let mut verified_by = Vec::new();
            let mut verdict = "unverified";
            for (name, s) in srcs {
                match s {
                    Src::Intact => verified_by.push(name.to_string()),
                    Src::Changed(v) => {
                        evidence.extend(v);
                        if verdict != "missing" {
                            verdict = "changed";
                        }
                    }
                    Src::Missing(e) => {
                        evidence.push(e);
                        verdict = "missing";
                    }
                    Src::Unverified(e) => evidence.push(e),
                }
            }
            if verdict == "unverified" && !verified_by.is_empty() {
                verdict = "intact";
            }
            match verdict {
                "changed" | "missing" => counts.guard_escapes += 1,
                "unverified" => counts.unverified_canaries += 1,
                _ => {}
            }
            canaries.push(CanaryRow {
                id: c.id.clone(),
                trap: c.trap.clone(),
                kind: c.kind.clone(),
                path: c.path.clone(),
                name: c.name.clone(),
                verdict: verdict.to_string(),
                verified_by,
                evidence,
            });
        }
    }

    // Trap items.
    let groups: Vec<String> = if cx.groups.is_empty() { vec!["main".into()] } else { cx.groups.to_vec() };
    let eff_by_op: HashMap<u32, &EffectRow> = effects.iter().map(|e| (e.op, e)).collect();
    let mut traps = Vec::new();
    for m in cx.manifests {
        for t in &m.traps {
            let mut items = Vec::new();
            for it in t.items.iter().filter(|i| groups.contains(&i.group)) {
                let tc = it.target.canonical(cx.sid).canon_string();
                let ri = rep.items.iter().find(|r| r.item == it.id).or_else(|| {
                    rep.items.iter().find(|r| canon::ci_eq(&r.target.canonical(cx.sid).canon_string(), &tc))
                });
                let jo = ri.and_then(|r| j.op(r.op));
                let actual: Option<Outcome> =
                    jo.and_then(|o| o.effective.clone()).or_else(|| ri.map(|r| r.outcome.clone()));
                let cond = condition_status(t, it);
                let matched = actual.as_ref().map(|a| {
                    if it.expect.matches(a) {
                        "pass"
                    } else if it.accept.iter().any(|e| e.matches(a)) {
                        "accepted"
                    } else {
                        "mismatch"
                    }
                });
                let verdict = if cond == Some("unmet") && matched != Some("pass") {
                    "not-scored"
                } else if !m.dry_run && t.built != Some(true) {
                    "not-built"
                } else {
                    matched.unwrap_or("not-run")
                };
                match verdict {
                    "mismatch" | "not-run" | "not-built" => counts.trap_mismatches += 1,
                    "not-scored" => counts.not_scored += 1,
                    _ => {}
                }
                items.push(ItemRow {
                    id: it.id.clone(),
                    group: it.group.clone(),
                    target: tc,
                    action: it.action.clone(),
                    expect: it.expect.summary(),
                    accept: it.accept.iter().map(Expect::summary).collect(),
                    op: ri.map(|r| r.op),
                    candidate: ri.map(|r| r.item.clone()),
                    actual: actual.as_ref().map(Outcome::summary),
                    verdict: verdict.to_string(),
                    condition: it.condition.as_ref().map(|c| format!("{} ({c})", cond.unwrap_or("unknown"))),
                    effect: ri.and_then(|r| eff_by_op.get(&r.op)).map(|e| format!("{}: {}", e.verdict, e.detail)),
                    detail: jo.and_then(|o| o.done_detail.clone()),
                });
            }
            let mine: Vec<&CanaryRow> = canaries.iter().filter(|c| c.trap == t.id).collect();
            if items.is_empty() && mine.is_empty() {
                continue;
            }
            let esc = mine.iter().filter(|c| matches!(c.verdict.as_str(), "changed" | "missing")).count() as u64;
            let unv = mine.iter().filter(|c| c.verdict == "unverified").count() as u64;
            let bad_item = items.iter().any(|i| matches!(i.verdict.as_str(), "mismatch" | "not-run" | "not-built"));
            let verdict = if esc > 0 || unv > 0 || bad_item {
                "fail"
            } else if !items.is_empty() && items.iter().all(|i| i.verdict == "not-scored") {
                "not-scored"
            } else {
                "pass"
            };
            traps.push(TrapRow {
                id: t.id.clone(),
                gate: t.gate.clone(),
                manifest: m.source.clone(),
                verdict: verdict.to_string(),
                canaries: mine.len() as u64,
                canaries_intact: mine.iter().filter(|c| c.verdict == "intact").count() as u64,
                guard_escapes: esc,
                canaries_unverified: unv,
                items,
            });
        }
    }
    if cx.manifests.is_empty() {
        warnings.push("no trap or fixture manifest: no canaries and no trap items checked".into());
    }

    counts.collateral = collateral.len() as u64;
    counts.unexplained = unexplained.len() as u64;
    counts.inconsistencies = incons.len() as u64;
    let ok = counts.guard_escapes == 0
        && counts.collateral == 0
        && counts.missing_effects == 0
        && counts.changed_not_done == 0
        && counts.trap_mismatches == 0
        && counts.unverified_canaries == 0
        && counts.inconsistencies == 0;
    Ok(ExecdiffReport {
        schema: SCHEMA.to_string(),
        inputs: Inputs::default(),
        groups,
        sid: cx.sid.map(str::to_string),
        session: h.session.clone(),
        plan_hash: h.plan_hash.clone(),
        journal_state: j.state().to_string(),
        restore_point: rep.restore_point.kind.clone(),
        ok,
        counts,
        canaries,
        traps,
        collateral,
        unexplained,
        effects,
        inconsistencies: incons,
        warnings,
    })
}

pub fn cmd_execdiff(a: &ExecdiffArgs) -> Result<ExecdiffReport> {
    let sa = Snap::load(&a.before, LoadOpts::default())?;
    let sb = Snap::load(&a.after, LoadOpts::default())?;
    let journal =
        parse_journal(&read_journal_text(&a.journal)?).with_context(|| format!("journal {}", a.journal.display()))?;
    let report =
        parse_report(&jsonio::read_text(&a.report)?).with_context(|| format!("report {}", a.report.display()))?;
    let deep_a = a.deep_before.as_deref().map(read_deep).transpose()?;
    let deep_b = a.deep_after.as_deref().map(read_deep).transpose()?;
    if deep_a.is_some() && deep_b.is_none() {
        bail!("--deep-before needs --deep-after");
    }
    let ambient = a.ambient.as_deref().map(AmbientSet::load).transpose()?;
    // SID for HKCU and the manifests' {user-sid}: --sid, a built manifest's user_sid, the deep doc, the snapshot.
    let mut texts = Vec::new();
    for p in &a.traps {
        texts.push((p, jsonio::read_text(p)?));
    }
    let manifest_sid = texts.iter().find_map(|(_, t)| {
        let v: Value = serde_json::from_str(t).ok()?;
        v.get("user_sid").and_then(Value::as_str).filter(|s| !s.starts_with('{')).map(str::to_string)
    });
    let sid = a
        .sid
        .clone()
        .or(manifest_sid)
        .or_else(|| deep_a.as_ref().and_then(|d| d.sid.clone()))
        .or_else(|| sa.guess_user_sid());
    let mut manifests = Vec::new();
    let mut mw = Vec::new();
    for (p, t) in &texts {
        let (m, w) = parse_manifest(t, &p.display().to_string(), sid.as_deref())
            .with_context(|| format!("manifest {}", p.display()))?;
        manifests.push(m);
        mw.extend(w);
    }
    let mut rep = check(&Ctx {
        a: &sa,
        b: &sb,
        journal: &journal,
        report: &report,
        manifests: &manifests,
        ambient: ambient.as_ref(),
        deep_a: deep_a.as_ref(),
        deep_b: deep_b.as_ref(),
        groups: &a.groups,
        sid: sid.as_deref(),
    })?;
    rep.warnings.extend(mw);
    let s = |p: &std::path::Path| p.display().to_string();
    rep.inputs = Inputs {
        before: s(&a.before),
        after: s(&a.after),
        journal: s(&a.journal),
        report: s(&a.report),
        traps: a.traps.iter().map(|p| s(p)).collect(),
        ambient: a.ambient.as_deref().map(s),
        deep_before: a.deep_before.as_deref().map(s),
        deep_after: a.deep_after.as_deref().map(s),
    };
    jsonio::write(&a.out, &rep)?;
    let c = &rep.counts;
    eprintln!(
        "execdiff: guard_escapes {}  collateral {}  unexplained {}  missing_effects {}  changed_not_done {}  \
         trap_mismatches {}  unverified canaries {} effects {}  inconsistencies {}",
        c.guard_escapes,
        c.collateral,
        c.unexplained,
        c.missing_effects,
        c.changed_not_done,
        c.trap_mismatches,
        c.unverified_canaries,
        c.unverified_effects,
        c.inconsistencies
    );
    for t in rep.traps.iter().filter(|t| t.verdict != "pass") {
        eprintln!("execdiff: trap {} {}", t.id, t.verdict);
    }
    for w in &rep.warnings {
        eprintln!("execdiff: warning: {w}");
    }
    eprintln!("execdiff: {} -> {}", if rep.ok { "ok" } else { "FAILED" }, a.out.display());
    Ok(rep)
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fidelity::journal::fixture::{self, HASH_A, HASH_B, SESSION, blocked, done};
    use crate::snap::{write_d, write_f, write_k, write_v};
    use crate::testutil::snap_with_roots;
    use serde_json::json;

    const R: &str = "C:\\Program Files\\PurgeTrapApp";
    const C: &str = "C:\\PurgeCanary";
    const K: &str = "HKLM\\SOFTWARE\\PurgeTrapApp";
    const KC: &str = "HKLM\\SOFTWARE\\PurgeCanary";
    const ROOTS: &[&str] = &[
        "C:\\Program Files",
        "C:\\ProgramData",
        "C:\\PurgeCanary",
        "C:\\cr",
        "HKLM\\SOFTWARE",
        "HKLM\\SYSTEM\\CurrentControlSet",
        "HKU\\S-1-5-21-1\\Software",
    ];
    const Q: &str = "C:\\ProgramData\\Purge\\Quarantine\\20261115T101502Z-9f3a6c1d2b7e4a50";

    /// What a test changes in the after snapshot.
    #[derive(Default, Clone)]
    struct Var {
        drop_canary: bool,
        drop_keep_value: bool,
        moved_file_stays: bool,
        canary_size: Option<u64>,
        /// Extra records written into the before (false) and after (true) snapshot.
        extra: Option<fn(&mut String, bool)>,
    }

    fn before_text(t: &mut String) {
        write_d(t, "C:\\Program Files", 0x10, 1, 0);
        write_d(t, R, 0x10, 1, 0);
        write_d(t, &format!("{R}\\odd"), 0x10, 5, 0);
        write_f(t, &format!("{R}\\odd\\name."), 13, 0x20, 5, 0);
        write_f(t, &format!("{R}\\odd\\name"), 7, 0x20, 5, 0);
        write_d(t, &format!("{R}\\links-j"), 0x10, 6, 0);
        write_d(t, &format!("{R}\\links-j\\j"), 0x410, 6, 0xA000_0003);
        write_d(t, "C:\\ProgramData", 0x10, 1, 0);
        write_d(t, "C:\\ProgramData\\Purge", 0x10, 1, 0);
        write_d(t, "C:\\ProgramData\\Purge\\Quarantine", 0x10, 1, 0);
        write_d(t, "C:\\ProgramData\\Microsoft", 0x10, 1, 0);
        write_f(t, "C:\\ProgramData\\Microsoft\\churn.log", 10, 0x20, 1, 0);
        write_d(t, C, 0x10, 1, 0);
        write_d(t, &format!("{C}\\links-j"), 0x10, 1, 0);
        write_d(t, &format!("{C}\\links-j\\target"), 0x10, 1, 0);
        write_f(t, &format!("{C}\\links-j\\target\\a.txt"), 20, 0x20, 1, 0);
        write_d(t, "C:\\cr", 0x10, 1, 0);
        write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(3));
        write_k(t, K, 1, Some(0), Some(3));
        write_k(t, &format!("{K}\\Values"), 1, Some(3), Some(0));
        write_v(t, &format!("{K}\\Values"), "del", 1, 4, 0x11, "x");
        write_v(t, &format!("{K}\\Values"), "keep", 1, 4, 0x12, "k");
        write_v(t, &format!("{K}\\Values"), "Path", 2, 8, 0x13, "a;b");
        write_k(t, &format!("{K}\\Tree"), 1, Some(1), Some(1));
        write_v(t, &format!("{K}\\Tree"), "", 1, 2, 0x21, "d");
        write_k(t, &format!("{K}\\Tree\\Sub"), 1, Some(1), Some(0));
        write_v(t, &format!("{K}\\Tree\\Sub"), "v", 4, 4, 0x22, "1");
        write_k(t, &format!("{K}\\Link"), 1, Some(1), Some(0));
        write_v(
            t,
            &format!("{K}\\Link"),
            "SymbolicLinkValue",
            6,
            40,
            0x23,
            "\\REGISTRY\\MACHINE\\SOFTWARE\\PurgeCanary\\Target",
        );
        write_k(t, KC, 1, Some(0), Some(1));
        write_k(t, &format!("{KC}\\Target"), 1, Some(2), Some(0));
        write_v(t, &format!("{KC}\\Target"), "CanaryValue", 1, 8, 0x31, "c");
        write_v(t, &format!("{KC}\\Target"), "CanaryDword", 4, 4, 0x32, "1");
        write_k(t, "HKLM\\SYSTEM\\CurrentControlSet", 1, Some(0), Some(0));
    }

    fn snaps(v: &Var) -> (Snap, Snap) {
        let a = snap_with_roots(ROOTS, |t| {
            before_text(t);
            if let Some(f) = v.extra {
                f(t, false);
            }
        });
        let b = snap_with_roots(ROOTS, |t| {
            if let Some(f) = v.extra {
                f(t, true);
            }
            write_d(t, "C:\\Program Files", 0x10, 1, 0);
            write_d(t, R, 0x10, 1, 0);
            // Moved out: the parent's mtime changes.
            write_d(t, &format!("{R}\\odd"), 0x10, if v.moved_file_stays { 5 } else { 9 }, 0);
            if v.moved_file_stays {
                write_f(t, &format!("{R}\\odd\\name."), 13, 0x20, 5, 0);
            }
            write_f(t, &format!("{R}\\odd\\name"), 7, 0x20, 5, 0);
            write_d(t, &format!("{R}\\links-j"), 0x10, 6, 0);
            write_d(t, &format!("{R}\\links-j\\j"), 0x410, 6, 0xA000_0003);
            write_d(t, "C:\\ProgramData", 0x10, 1, 0);
            write_d(t, "C:\\ProgramData\\Purge", 0x10, 1, 0);
            write_d(t, "C:\\ProgramData\\Purge\\Quarantine", 0x10, 9, 0);
            write_d(t, Q, 0x10, 9, 0);
            write_d(t, &format!("{Q}\\000001"), 0x10, 9, 0);
            write_f(t, &format!("{Q}\\000001\\name."), 13, 0x20, 5, 0);
            write_d(t, "C:\\ProgramData\\Microsoft", 0x10, 1, 0);
            write_f(t, "C:\\ProgramData\\Microsoft\\churn.log", 99, 0x20, 2, 0);
            write_d(t, C, 0x10, 1, 0);
            write_d(t, &format!("{C}\\links-j"), 0x10, 1, 0);
            write_d(t, &format!("{C}\\links-j\\target"), 0x10, if v.drop_canary { 9 } else { 1 }, 0);
            if !v.drop_canary {
                write_f(t, &format!("{C}\\links-j\\target\\a.txt"), v.canary_size.unwrap_or(20), 0x20, 1, 0);
            }
            write_d(t, "C:\\cr", 0x10, 7, 0);
            write_d(t, "C:\\cr\\out", 0x10, 7, 0);
            write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(3));
            write_k(t, K, 2, Some(0), Some(2));
            write_k(t, &format!("{K}\\Values"), 2, Some(if v.drop_keep_value { 1 } else { 2 }), Some(0));
            if !v.drop_keep_value {
                write_v(t, &format!("{K}\\Values"), "keep", 1, 4, 0x12, "k");
            }
            write_v(t, &format!("{K}\\Values"), "Path", 2, 4, 0x14, "a");
            write_k(t, &format!("{K}\\Link"), 1, Some(1), Some(0));
            write_v(
                t,
                &format!("{K}\\Link"),
                "SymbolicLinkValue",
                6,
                40,
                0x23,
                "\\REGISTRY\\MACHINE\\SOFTWARE\\PurgeCanary\\Target",
            );
            write_k(t, KC, 1, Some(0), Some(1));
            write_k(t, &format!("{KC}\\Target"), 1, Some(2), Some(0));
            write_v(t, &format!("{KC}\\Target"), "CanaryValue", 1, 8, 0x31, "c");
            write_v(t, &format!("{KC}\\Target"), "CanaryDword", 4, 4, 0x32, "1");
            write_k(t, "HKLM\\SYSTEM\\CurrentControlSet", 1, Some(0), Some(0));
        });
        (a, b)
    }

    /// (op, kind, a, b, c, dir, intent, journal outcome)
    type PlanRow = (u32, &'static str, String, &'static str, &'static str, bool, bool, Value);

    fn plan(junction_outcome: Value) -> Vec<PlanRow> {
        let jdone = junction_outcome.get("kind") == Some(&json!("Done"));
        vec![
            (1, "QuarantineMove", format!("{R}\\odd\\name."), "", "", false, true, done()),
            (2, "QuarantineMove", format!("{R}\\links-j\\j"), "", "", true, jdone, junction_outcome),
            (3, "DeleteValue", format!("{K}\\Values"), "del", "", false, true, done()),
            (4, "DeleteKeyTree", format!("{K}\\Tree"), "", "", false, true, done()),
            (5, "EditSegment", format!("{K}\\Values"), "Path", "b", false, true, done()),
            (6, "DeleteKeyTree", format!("{K}\\Link"), "", "", false, false, blocked("RegLink")),
        ]
    }

    fn journal_text(p: &[PlanRow]) -> String {
        let recs: Vec<Value> = p
            .iter()
            .flat_map(|(op, k, a, b, c, dir, i, o)| fixture::op(*op, k, a, b, c, *dir, *i, o.clone()))
            .collect();
        fixture::text(p.len(), &recs)
    }

    fn exec_op_json(kind: &str, a: &str, b: &str, c: &str) -> Value {
        match kind {
            "QuarantineMove" | "RemoveDirIfEmpty" => json!({"kind": kind, "path": a}),
            "DeleteKeyTree" | "DeleteKeyIfEmpty" => json!({"kind": kind, "key": a}),
            "DeleteValue" => json!({"kind": kind, "key": a, "name": b}),
            "EditSegment" => json!({"kind": kind, "key": a, "name": b, "segment": c}),
            _ => json!({"kind": kind, "full_name": a}),
        }
    }

    fn target_json(kind: &str, a: &str, b: &str, c: &str) -> Value {
        match kind {
            "QuarantineMove" | "RemoveDirIfEmpty" => json!({"type": "Path", "path": a}),
            "DeleteKeyTree" | "DeleteKeyIfEmpty" => json!({"type": "RegKey", "path": a}),
            "DeleteValue" => json!({"type": "RegValue", "path": a, "name": b}),
            "EditSegment" => {
                json!({"type": "RegMultiSzSegment", "path": a, "name": b, "segment": c})
            }
            _ => json!({"type": "AppxPackage", "full_name": a}),
        }
    }

    /// A `purge.exec/1` report as purge-model writes it.
    fn report_text(p: &[PlanRow]) -> String {
        let mut counts = OutcomeCounts::default();
        let items: Vec<Value> = p
            .iter()
            .map(|(op, k, a, b, c, _, _, o)| {
                counts.record(&serde_json::from_value(o.clone()).unwrap());
                json!({"item": format!("c-{op:02}"), "op": op, "target": target_json(k, a, b, c),
                    "exec_op": exec_op_json(k, a, b, c), "outcome": o, "backup_bytes": 0})
            })
            .collect();
        json!({"schema": "purge.exec/1", "session": SESSION, "app": "fixture", "plan_hash": HASH_A,
            "selection_hash": HASH_B, "state": "Committed", "started": 1, "finished": 2, "items": items,
            "counts": counts, "backup_bytes": 0, "pending_reboot": false, "restore_point": {"kind": "NotRequested"},
            "warnings": []})
        .to_string()
    }

    fn manifest_text() -> String {
        let blockedx = |b: &str| json!({"outcome": "Skipped", "reason": "GateBlocked", "blocker": b, "summary": "x"});
        let donex = json!({"outcome": "Done", "reason": null, "blocker": null, "summary": "x"});
        json!({
            "schema": "purge.rig.m2traps/0", "dry_run": true, "user_sid": "{user-sid}",
            "traps": [
                {"id": "link-junction-item", "gate": "G1", "build": null, "items": [
                    {"id": "link-junction-item.link", "target": {"type": "Path", "path": format!("{R}\\links-j\\j")},
                     "action": "Quarantine", "group": "main", "expect": blockedx("ReparseMismatch"), "accept": [], "condition": null}]},
                {"id": "odd-names", "gate": "G1", "build": null, "items": [
                    {"id": "odd-names.dot", "target": {"type": "Path", "path": format!("{R}\\odd\\name.")},
                     "action": "Quarantine", "group": "main", "expect": donex, "accept": [], "condition": null},
                    {"id": "odd-names.race", "target": {"type": "Path", "path": format!("{R}\\race")},
                     "action": "Quarantine", "group": "race-a", "expect": donex, "accept": [], "condition": null}]},
                {"id": "reglink-leaf", "gate": "G1", "build": null, "items": [
                    {"id": "reglink-leaf.key", "target": {"type": "RegKey", "path": format!("{K}\\Link")},
                     "action": "DeleteKey", "group": "main", "expect": blockedx("RegLink"), "accept": [], "condition": null}]}
            ],
            "canaries": [
                {"id": "links-j.a", "trap": "link-junction-item", "kind": "file", "path": format!("{C}\\links-j\\target\\a.txt"),
                 "sha256": HASH_A},
                {"id": "odd.sibling", "trap": "odd-names", "kind": "file", "path": format!("{R}\\odd\\name"), "sha256": HASH_B},
                {"id": "reglink.target", "trap": "reglink-leaf", "kind": "regkey", "path": format!("{KC}\\Target"), "sha256": HASH_A},
                {"id": "reglink.value", "trap": "reglink-leaf", "kind": "regvalue", "path": format!("{KC}\\Target"),
                 "name": "CanaryValue", "sha256": HASH_A}
            ]
        })
        .to_string()
    }

    fn ambient() -> AmbientSet {
        AmbientSet {
            union: crate::ambient::Matcher::new("u", &["P:C:\\ProgramData\\Microsoft\\churn.log".to_string()], &[])
                .unwrap(),
            runs: Vec::new(),
            records: None,
        }
    }

    fn chg(op: char, rec: char, path: &str) -> Change {
        Change { op, rec, path: path.into(), name: None, changes: Vec::new() }
    }

    #[test]
    fn engine_rm_is_the_restart_manager_subtree_only() {
        assert!(is_engine_rm(&chg('+', 'K', "HKU\\S-1-5-21-1\\Software\\Microsoft\\RestartManager")));
        assert!(is_engine_rm(&chg('-', 'K', "HKU\\S-1-5-21-1\\Software\\Microsoft\\RestartManager\\Session0000")));
        assert!(is_engine_rm(&chg('+', 'V', "HKU\\S-1-5-21-1\\Software\\Microsoft\\RestartManager\\Session0000")));
        assert!(!is_engine_rm(&chg('~', 'K', "HKU\\S-1-5-21-1\\Software\\Microsoft")));
        assert!(!is_engine_rm(&chg('-', 'K', "HKU\\S-1-5-21-1\\Software\\Microsoft\\RestartManagerX")));
        assert!(!is_engine_rm(&chg('-', 'K', "HKLM\\SOFTWARE\\Microsoft\\RestartManager")));
        assert!(!is_engine_rm(&chg('-', 'F', "C:\\HKU\\x\\Software\\Microsoft\\RestartManager")));
    }

    #[test]
    fn engine_rp_is_a_vss_diag_change_never_a_removal() {
        assert!(is_engine_rp(&chg('~', 'K', "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VSS\\Diag")));
        assert!(is_engine_rp(&chg('~', 'V', "HKLM\\SYSTEM\\ControlSet001\\Services\\VSS\\Diag\\SystemRestore")));
        assert!(is_engine_rp(&chg('+', 'K', "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VSS\\Diag\\X")));
        assert!(!is_engine_rp(&chg('-', 'K', "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VSS\\Diag")));
        assert!(!is_engine_rp(&chg('-', 'V', "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VSS\\Diag\\X")));
        assert!(!is_engine_rp(&chg('~', 'K', "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VSS")));
        assert!(!is_engine_rp(&chg('~', 'K', "HKLM\\SYSTEM\\ControlSetX01\\Services\\VSS\\Diag")));
        assert!(!is_engine_rp(&chg('~', 'F', "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VSS\\Diag")));
    }

    fn chgv(op: char, path: &str, name: &str) -> Change {
        Change { op, rec: 'V', path: path.into(), name: Some(name.into()), changes: Vec::new() }
    }

    fn chgx(op: char, rec: char, path: &str, changes: &[&str]) -> Change {
        Change { op, rec, path: path.into(), name: None, changes: changes.iter().map(|s| s.to_string()).collect() }
    }

    const CLASS: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{533c5b84-ec70-11d2-9505-00c04f79deaf}";
    const BASEC: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceContainers\\{00000000-0000-0000-FFFF-FFFFFFFFFFFF}\\BaseContainers\\{00000000-0000-0000-FFFF-FFFFFFFFFFFF}";
    const SRPROV: &str = "HKLM\\SOFTWARE\\Microsoft\\Wbem\\Tracing\\Providers\\SystemRestoreProv @ root/default";
    const FWPROV: &str = "HKLM\\SOFTWARE\\Microsoft\\Wbem\\Tracing\\Providers\\wfascim @ ROOT/StandardCimv2";

    #[test]
    fn engine_rp_created_records_are_additions_and_changes_only() {
        let yes = [
            chg('+', 'K', &format!("{CLASS}\\0001")),
            chgv('+', &format!("{CLASS}\\0001"), "DriverDesc"),
            chg('+', 'K', "HKLM\\SYSTEM\\ControlSet001\\Control\\Class\\{533C5B84-EC70-11D2-9505-00C04F79DEAF}\\0012"),
            chgv('+', BASEC, "STORAGE\\VolumeSnapshot\\HarddiskVolumeSnapshot2"),
            chgv('+', SRPROV, "134395554330118898"),
            chgx('~', 'K', SRPROV, &["lwt 1->2", "n_values 1->2"]),
            chgv('~', "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SPP", "LastIndex"),
            chgv('~', "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore", "LastIndex"),
            chgv('~', "HKLM\\SYSTEM\\CurrentControlSet\\Services\\DsmSvc\\State", "SessionNumber"),
            chgx('~', 'D', "C:\\System Volume Information", &["mtime 1->2"]),
            chgx('~', 'F', "C:\\Users\\tester\\ntuser.dat.LOG2", &["size 442368->8192"]),
            chgx('~', 'F', "C:\\Users\\tester\\NTUSER.DAT.LOG1", &["size 0->1", "mtime 1->2"]),
            chgx(
                '~',
                'F',
                "C:\\Users\\tester\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG1",
                &["size 0->147456"],
            ),
        ];
        for c in &yes {
            assert!(is_engine_rp_created(c), "{c:?}");
        }
        let no = [
            // Hive logs: removed, added, a content-hash or attribute change, the hive itself, another log name,
            // another folder, a nested profile path.
            chgx('-', 'F', "C:\\Users\\tester\\ntuser.dat.LOG2", &[]),
            chg('+', 'F', "C:\\Users\\tester\\ntuser.dat.LOG2"),
            chgx('~', 'F', "C:\\Users\\tester\\ntuser.dat.LOG2", &["size 1->2", "sha256 a->b"]),
            chgx('~', 'F', "C:\\Users\\tester\\ntuser.dat.LOG2", &["attrs 32->0"]),
            chgx('~', 'F', "C:\\Users\\tester\\ntuser.dat", &["size 1->2"]),
            chgx('~', 'F', "C:\\Users\\tester\\ntuser.dat.LOG3", &["size 1->2"]),
            chgx('~', 'F', "C:\\Users\\tester\\Documents\\ntuser.dat.LOG1", &["size 1->2"]),
            chgx('~', 'F', "C:\\Users\\tester\\AppData\\Local\\UsrClass.dat.LOG1", &["size 1->2"]),
            chgx('~', 'F', "C:\\ProgramData\\ntuser.dat.LOG1", &["size 1->2"]),
            // Removals never.
            chg('-', 'K', &format!("{CLASS}\\0001")),
            chgv('-', &format!("{CLASS}\\0001"), "DriverDesc"),
            chgv('-', BASEC, "STORAGE\\VolumeSnapshot\\HarddiskVolumeSnapshot2"),
            chgv('-', "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SPP", "LastIndex"),
            chg('-', 'K', SRPROV),
            // Changes of an existing device instance, another class, a deeper key, a non-numeric instance.
            chgv('~', &format!("{CLASS}\\0001"), "DriverDesc"),
            chg(
                '+',
                'K',
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e967-e325-11ce-bfc1-08002be10318}\\0001",
            ),
            chg('+', 'K', &format!("{CLASS}\\0001\\Properties")),
            chg('+', 'K', &format!("{CLASS}\\Configuration")),
            // Another container value, another container.
            chgv('+', BASEC, "STORAGE\\Volume\\{x}"),
            chgv('+', BASEC, "STORAGE\\VolumeSnapshot\\HarddiskVolumeSnapshot"),
            chgv(
                '+',
                &BASEC.replace("FFFF-FFFFFFFFFFFF}\\BaseContainers", "FFFF-FFFFFFFFFFFE}\\BaseContainers"),
                "STORAGE\\VolumeSnapshot\\HarddiskVolumeSnapshot2",
            ),
            // Another tracing provider, a named value, a key change beyond lwt / count.
            chgv('+', FWPROV, "134395554415537810"),
            chgv('+', SRPROV, "Level"),
            chgx('~', 'K', SRPROV, &["lwt 1->2", "n_subkeys 0->1"]),
            // Other SPP / DsmSvc values, a ControlSet look-alike.
            chgv('~', "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SPP", "LastIndexX"),
            chgv('~', "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore", "RPSessionInterval"),
            chgv('~', "HKLM\\SYSTEM\\CurrentControlSet\\Services\\DsmSvc\\Parameters", "SessionNumber"),
            chgv('~', "HKLM\\SYSTEM\\ControlSetX01\\Services\\DsmSvc\\State", "SessionNumber"),
            // System Volume Information: anything but the directory's mtime.
            chgx('~', 'D', "C:\\System Volume Information", &["mtime 1->2", "attrs 22->20"]),
            chgx('~', 'F', "C:\\System Volume Information\\tracking.log", &["mtime 1->2"]),
            chgx('~', 'D', "C:\\x\\System Volume Information", &["mtime 1->2"]),
        ];
        for c in &no {
            assert!(!is_engine_rp_created(c), "{c:?}");
        }
    }

    #[test]
    fn engine_fw_delete_records_are_additions_and_changes_only() {
        let yes = [
            chgx('~', 'K', FWPROV, &["lwt 1->2"]),
            chg('+', 'K', FWPROV),
            chgv('+', FWPROV, "134395554415537810"),
            chgv('~', "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Epoch", "Epoch"),
            chgx('~', 'F', "C:\\ProgramData\\Microsoft\\Windows\\wfp\\wfpdiag.etl", &["size 1->2", "mtime 1->2"]),
        ];
        for c in &yes {
            assert!(is_engine_fw_delete(c), "{c:?}");
        }
        let no = [
            chg('-', 'K', FWPROV),
            chgv('-', "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Epoch", "Epoch"),
            chg('-', 'F', "C:\\ProgramData\\Microsoft\\Windows\\wfp\\wfpdiag.etl"),
            chgv('~', "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters", "Epoch"),
            chgv('~', "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Epoch", "Other"),
            chgv(
                '-',
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules",
                "X",
            ),
            chgx('~', 'K', "HKLM\\SOFTWARE\\Microsoft\\Wbem\\Tracing\\Providers\\CIMWin32 @ root/CIMV2", &["lwt 1->2"]),
            chgx('~', 'K', SRPROV, &["lwt 1->2"]),
            chgx('~', 'F', "C:\\ProgramData\\Microsoft\\Windows\\wfp\\wfpdiag2.etl", &["mtime 1->2"]),
            chg('+', 'F', "C:\\ProgramData\\Microsoft\\Windows\\wfp\\wfpdiag.etl"),
        ];
        for c in &no {
            assert!(!is_engine_fw_delete(c), "{c:?}");
        }
    }

    const BAM: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-1";
    const BAM_BROKER: &str = "\\Device\\HarddiskVolume3\\Program Files\\Purge\\purge-broker.exe";
    const PCA: &str = "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store";

    #[test]
    fn broker_exit_is_the_brokers_bam_and_pca_values_added_or_changed() {
        let yes = [
            chgv('~', BAM, BAM_BROKER),
            chgv('+', BAM, BAM_BROKER),
            chgv('~', &BAM.replace("CurrentControlSet", "ControlSet001"), BAM_BROKER),
            chgv('~', BAM, "\\Device\\HarddiskVolume12\\PROGRAM FILES\\purge\\PURGE-BROKER.EXE"),
            chgv('~', PCA, "C:\\Program Files\\Purge\\purge-broker.exe"),
            chgv('+', PCA, "c:\\program files\\purge\\purge-broker.exe"),
            chgv('+', &PCA.replace("HKU\\", "HKEY_USERS\\"), "C:\\Program Files\\Purge\\purge-broker.exe"),
        ];
        for c in &yes {
            assert!(is_broker_exit(c), "{c:?}");
        }
        let no = [
            // A removal never.
            chgv('-', BAM, BAM_BROKER),
            chgv('-', PCA, "C:\\Program Files\\Purge\\purge-broker.exe"),
            // Another image: cmd.exe, the UI, the engine, a look-alike name or folder.
            chgv('~', BAM, "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe"),
            chgv('~', BAM, "\\Device\\HarddiskVolume3\\Program Files\\Purge\\Purge.exe"),
            chgv('~', BAM, "\\Device\\HarddiskVolume3\\Program Files\\Purge\\purge-engine.exe"),
            chgv('~', BAM, "\\Device\\HarddiskVolume3\\Program Files\\Purge\\purge-broker.exe.bak"),
            chgv('~', BAM, "\\Device\\HarddiskVolume3\\Program Files\\PurgeX\\purge-broker.exe"),
            chgv('~', BAM, "\\Program Files\\Purge\\purge-broker.exe"),
            chgv('~', BAM, "\\Device\\HarddiskVolume4\\Users\\x\\Program Files\\Purge\\purge-broker.exe"),
            chgv('~', BAM, "\\Device\\HarddiskVolume\\Program Files\\Purge\\purge-broker.exe"),
            chgv('~', BAM, "\\Device\\Mup\\Program Files\\Purge\\purge-broker.exe"),
            chgv('~', PCA, "C:\\Windows\\System32\\cmd.exe"),
            chgv('~', PCA, "D:\\Program Files\\Purge\\purge-broker.exe"),
            chgv('~', PCA, "C:\\Program Files\\Purge\\purge-broker.exe.x"),
            chgv('~', PCA, "\\Device\\HarddiskVolume3\\Program Files\\Purge\\purge-broker.exe"),
            // Other places: bam's other keys, another SID shape, a deeper key, the store's parent, HKLM.
            chgv('~', "HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings", BAM_BROKER),
            chgv('~', "HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\x", BAM_BROKER),
            chgv('~', &format!("{BAM}\\Sub"), BAM_BROKER),
            chgv('~', "HKLM\\SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings\\S-1-5-21-1", BAM_BROKER),
            chgv('~', "HKLM\\SYSTEM\\ControlSetX01\\Services\\bam\\State\\UserSettings\\S-1-5-21-1", BAM_BROKER),
            chgv('~', &PCA.replace("\\Store", ""), "C:\\Program Files\\Purge\\purge-broker.exe"),
            chgv('~', &format!("{PCA}\\Sub"), "C:\\Program Files\\Purge\\purge-broker.exe"),
            chgv('~', &PCA.replace("HKU\\S-1-5-21-1", "HKLM"), "C:\\Program Files\\Purge\\purge-broker.exe"),
            chgv('~', &PCA.replace("S-1-5-21-1", "x"), "C:\\Program Files\\Purge\\purge-broker.exe"),
            chgv('~', &PCA.replace("S-1-5-21-1", "S-1-5-21-1_Classes"), "C:\\Program Files\\Purge\\purge-broker.exe"),
            chgv('~', "HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-x", BAM_BROKER),
            // Keys and files are never covered (the key's LastWriteTime is the parent rule's).
            chgx('~', 'K', BAM, &["lwt 1->2"]),
            chgx('~', 'K', PCA, &["lwt 1->2", "n_values 1->2"]),
            chg('+', 'K', PCA),
            chg('~', 'F', "C:\\Program Files\\Purge\\purge-broker.exe"),
        ];
        for c in &no {
            assert!(!is_broker_exit(c), "{c:?}");
        }
    }

    /// The broker's exit records in the snapshots: before (`after` false) and after. bam value changed, the PCA
    /// value added (its key's LastWriteTime / value count change with it).
    fn broker_exit_snaps(t: &mut String, after: bool) {
        let (lwt, nv, h) = if after { (2, 1, 2) } else { (1, 0, 1) };
        write_k(t, BAM, lwt, Some(2), Some(0));
        write_v(t, BAM, BAM_BROKER, 3, 24, h, "x");
        write_v(t, BAM, "SequenceNumber", 4, 4, 9, "1");
        write_k(t, PCA, lwt, Some(nv), Some(0));
        if after {
            write_v(t, PCA, "C:\\Program Files\\Purge\\purge-broker.exe", 3, 48, 7, "x");
        }
    }

    #[test]
    fn broker_exit_records_are_authorised_and_their_keys_by_the_parent_rule() {
        let r = run(Case { var: Var { extra: Some(broker_exit_snaps), ..Default::default() }, ..Default::default() });
        assert!(r.ok, "{:#?}", (&r.counts, &r.collateral, &r.unexplained));
        assert_eq!((r.counts.collateral, r.counts.unexplained), (0, 0), "{:#?}", (&r.collateral, &r.unexplained));
        assert_eq!(r.counts.authorised.get("broker-exit").copied(), Some(2), "{:?}", r.counts.authorised);
        // Both keys' LastWriteTime (and the PCA key's value count) are parents of an authorised value.
        let base = run(Case::default());
        let parents = |x: &ExecdiffReport| x.counts.authorised.get("parent").copied().unwrap_or(0);
        assert_eq!(parents(&r), parents(&base) + 2, "{:?}", r.counts.authorised);
    }

    /// A removed broker value and a changed value of another image: collateral, with their keys.
    fn broker_exit_wrong_snaps(t: &mut String, after: bool) {
        let lwt = if after { 2 } else { 1 };
        write_k(t, BAM, lwt, Some(if after { 1 } else { 2 }), Some(0));
        if !after {
            write_v(t, BAM, BAM_BROKER, 3, 24, 1, "x");
        }
        write_v(t, BAM, "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe", 3, 24, lwt, "x");
        write_k(t, PCA, lwt, Some(1), Some(0));
        write_v(t, PCA, "C:\\Windows\\System32\\cmd.exe", 3, 48, lwt, "x");
    }

    #[test]
    fn broker_exit_never_covers_a_removal_or_another_image() {
        let r =
            run(Case { var: Var { extra: Some(broker_exit_wrong_snaps), ..Default::default() }, ..Default::default() });
        assert!(!r.ok);
        assert_eq!(r.counts.authorised.get("broker-exit"), None, "{:?}", r.counts.authorised);
        let got: Vec<(String, String, Option<String>)> =
            r.collateral.iter().map(|c| (c.change.clone(), c.path.clone(), c.name.clone())).collect();
        for want in [
            ("-V", BAM, Some(BAM_BROKER)),
            ("~V", BAM, Some("\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe")),
            ("~V", PCA, Some("C:\\Windows\\System32\\cmd.exe")),
            ("~K", BAM, None),
            ("~K", PCA, None),
        ] {
            assert!(
                got.iter().any(|g| g.0 == want.0 && g.1.eq_ignore_ascii_case(want.1) && g.2.as_deref() == want.2),
                "{want:?} not collateral: {got:#?}"
            );
        }
        assert_eq!(r.counts.collateral, 5, "{got:#?}");
    }

    const PF: &str = "C:\\WINDOWS\\Prefetch\\SVCHOST.EXE-C5EEC15E.pf";

    #[test]
    fn windows_prefetch_is_a_pf_file_in_prefetch_changed_in_size_or_mtime_only() {
        let yes = [
            chgx('~', 'F', PF, &["size 3482->4105", "mtime 1->2"]),
            chgx('~', 'F', PF, &["mtime 1->2"]),
            chgx('~', 'F', PF, &["size 1->2"]),
            chgx('~', 'F', "c:\\windows\\prefetch\\PURGE-BROKER.EXE-0A1B2C3D.PF", &["mtime 1->2"]),
            chgx('~', 'F', "D:\\Windows\\Prefetch\\NOTEPAD.EXE-12345678.pf", &["mtime 1->2"]),
        ];
        for c in &yes {
            assert!(is_windows_prefetch(c), "{c:?}");
        }
        let no = [
            // Added or removed: never (Purge's file ops only remove, so a removal must stay visible).
            chg('+', 'F', PF),
            chg('-', 'F', PF),
            // Another change than size / LastWriteTime, or none recorded.
            chgx('~', 'F', PF, &["attrs 20->21"]),
            chgx('~', 'F', PF, &["mtime 1->2", "reparse 0->a0000003"]),
            chgx('~', 'F', PF, &["kind F->D"]),
            chgx('~', 'F', PF, &[]),
            // Not a file, not a .pf, not directly in Prefetch, not the Windows folder.
            chgx('~', 'D', "C:\\WINDOWS\\Prefetch", &["mtime 1->2"]),
            chgx('~', 'D', PF, &["mtime 1->2"]),
            chgx('~', 'F', "C:\\WINDOWS\\Prefetch\\Layout.ini", &["mtime 1->2"]),
            chgx('~', 'F', "C:\\WINDOWS\\Prefetch\\ReadyBoot\\Trace1.fx", &["mtime 1->2"]),
            chgx('~', 'F', "C:\\WINDOWS\\Prefetch\\Sub\\X.EXE-12345678.pf", &["mtime 1->2"]),
            chgx('~', 'F', "C:\\WINDOWS\\Prefetch\\X.pf.bak", &["mtime 1->2"]),
            chgx('~', 'F', "C:\\Users\\x\\Windows\\Prefetch\\X.EXE-12345678.pf", &["mtime 1->2"]),
            chgx('~', 'F', "C:\\Program Files\\Prefetch\\X.EXE-12345678.pf", &["mtime 1->2"]),
            chgx('~', 'F', "\\\\?\\C:\\Windows\\Prefetch\\X.EXE-12345678.pf", &["mtime 1->2"]),
            chgx('~', 'F', "C:\\Windows\\Prefetch\\.pf", &["mtime 1->2"]),
        ];
        for c in &no {
            assert!(!is_windows_prefetch(c), "{c:?}");
        }
    }

    /// A prefetch trace rewritten in the window, and one added and one removed beside it.
    fn prefetch_snaps(t: &mut String, after: bool) {
        write_d(t, "C:\\WINDOWS", 0x10, 1, 0);
        write_d(t, "C:\\WINDOWS\\Prefetch", 0x10, 1, 0);
        write_f(t, PF, if after { 4105 } else { 3482 }, 0x20, if after { 2 } else { 1 }, 0);
    }

    fn prefetch_added_removed_snaps(t: &mut String, after: bool) {
        prefetch_snaps(t, after);
        let name = if after { "NEW.EXE-11111111.pf" } else { "OLD.EXE-22222222.pf" };
        write_f(t, &format!("C:\\WINDOWS\\Prefetch\\{name}"), 10, 0x20, 1, 0);
    }

    #[test]
    fn windows_prefetch_changes_are_authorised_additions_and_removals_are_not() {
        let r = run(Case { var: Var { extra: Some(prefetch_snaps), ..Default::default() }, ..Default::default() });
        assert!(r.ok, "{:#?}", (&r.counts, &r.collateral, &r.unexplained));
        assert_eq!((r.counts.collateral, r.counts.unexplained), (0, 0), "{:#?}", (&r.collateral, &r.unexplained));
        assert_eq!(r.counts.authorised.get("windows-prefetch").copied(), Some(1), "{:?}", r.counts.authorised);

        let r = run(Case {
            var: Var { extra: Some(prefetch_added_removed_snaps), ..Default::default() },
            ..Default::default()
        });
        assert!(!r.ok);
        assert_eq!(r.counts.authorised.get("windows-prefetch").copied(), Some(1), "{:?}", r.counts.authorised);
        let got: Vec<(String, String)> = r.collateral.iter().map(|c| (c.change.clone(), c.path.clone())).collect();
        assert!(got.iter().any(|g| g.0 == "-F" && g.1.ends_with("OLD.EXE-22222222.pf")), "{got:#?}");
        assert!(r.unexplained.iter().any(|u| u.path.ends_with("NEW.EXE-11111111.pf")), "{:#?}", r.unexplained);
    }

    struct Case {
        var: Var,
        junction: Value,
        report_override: Option<String>,
        manifest: String,
        deep: Option<(DeepDoc, DeepDoc)>,
    }

    impl Default for Case {
        fn default() -> Self {
            Case {
                var: Var::default(),
                junction: blocked("ReparseMismatch"),
                report_override: None,
                manifest: manifest_text(),
                deep: None,
            }
        }
    }

    fn run(c: Case) -> ExecdiffReport {
        let (a, b) = snaps(&c.var);
        let p = plan(c.junction.clone());
        let j = parse_journal(&journal_text(&p)).unwrap();
        let rep = parse_report(&c.report_override.unwrap_or_else(|| report_text(&p))).unwrap();
        let (m, w) = parse_manifest(&c.manifest, "m2-traps.json", Some("S-1-5-21-1")).unwrap();
        assert!(w.is_empty(), "{w:?}");
        let amb = ambient();
        let (da, db) = match &c.deep {
            Some((x, y)) => (Some(x), Some(y)),
            None => (None, None),
        };
        check(&Ctx {
            a: &a,
            b: &b,
            journal: &j,
            report: &rep,
            manifests: &[m],
            ambient: Some(&amb),
            deep_a: da,
            deep_b: db,
            groups: &[],
            sid: Some("S-1-5-21-1"),
        })
        .unwrap()
    }

    fn trap<'a>(r: &'a ExecdiffReport, id: &str) -> &'a TrapRow {
        r.traps.iter().find(|t| t.id == id).unwrap_or_else(|| panic!("trap {id}"))
    }

    #[test]
    fn clean_run_is_zero_zero() {
        let r = run(Case::default());
        assert!(r.ok, "{:#?}", (&r.counts, &r.collateral, &r.effects, &r.canaries, &r.inconsistencies));
        assert_eq!(
            (r.counts.guard_escapes, r.counts.collateral, r.counts.unexplained),
            (0, 0, 0),
            "{:#?}",
            r.unexplained
        );
        assert_eq!(r.counts.missing_effects, 0);
        for k in ["op", "store", "rig", "ambient", "parent"] {
            assert!(r.counts.authorised.get(k).copied().unwrap_or(0) > 0, "{k}: {:?}", r.counts.authorised);
        }
        assert_eq!(r.canaries.len(), 4);
        assert!(r.canaries.iter().all(|c| c.verdict == "intact" && c.verified_by == ["snap"]), "{:#?}", r.canaries);
        assert!(r.traps.iter().all(|t| t.verdict == "pass"), "{:#?}", r.traps);
        // The race item belongs to another group.
        assert_eq!(trap(&r, "odd-names").items.len(), 1);
        let jt = &trap(&r, "link-junction-item").items[0];
        assert_eq!((jt.verdict.as_str(), jt.actual.as_deref()), ("pass", Some("Skipped/GateBlocked/ReparseMismatch")));
        assert_eq!(jt.op, Some(2));
        let e: Vec<(&str, &str)> = r.effects.iter().map(|e| (e.verdict.as_str(), e.detail.as_str())).collect();
        assert_eq!(e[0], ("ok", "gone after"));
        assert_eq!(e[1], ("ok", "unchanged"));
        assert_eq!(e[4], ("ok", "value data changed"));
    }

    #[test]
    fn removed_canary_is_one_escape_naming_the_trap() {
        let r = run(Case { var: Var { drop_canary: true, ..Default::default() }, ..Default::default() });
        assert!(!r.ok);
        assert_eq!(r.counts.guard_escapes, 1);
        let c: Vec<&CanaryRow> = r.canaries.iter().filter(|c| c.verdict != "intact").collect();
        assert_eq!(c.len(), 1);
        assert_eq!((c[0].trap.as_str(), c[0].verdict.as_str()), ("link-junction-item", "missing"));
        let t = trap(&r, "link-junction-item");
        assert_eq!((t.verdict.as_str(), t.guard_escapes), ("fail", 1));
        // The deleted canary is also collateral; its parent's mtime change is not explained by it.
        assert!(r.collateral.iter().any(|d| d.change == "-F" && d.path.ends_with("a.txt")));
    }

    #[test]
    fn changed_canary_is_an_escape() {
        let r = run(Case { var: Var { canary_size: Some(21), ..Default::default() }, ..Default::default() });
        assert_eq!(r.counts.guard_escapes, 1);
        assert_eq!(r.counts.collateral, 1);
        assert!(
            r.canaries.iter().any(|c| c.verdict == "changed" && c.evidence.iter().any(|e| e.contains("size 20->21")))
        );
    }

    #[test]
    fn extra_deleted_value_is_one_collateral() {
        let r = run(Case { var: Var { drop_keep_value: true, ..Default::default() }, ..Default::default() });
        assert!(!r.ok);
        assert_eq!(r.counts.collateral, 1, "{:#?}", r.collateral);
        assert_eq!(
            r.collateral[0],
            DiffRow { change: "-V".into(), path: format!("{K}\\Values"), name: Some("keep".into()), changes: vec![] }
        );
        assert_eq!(r.counts.guard_escapes, 0);
    }

    #[test]
    fn done_without_visible_effect_is_flagged() {
        let r = run(Case { var: Var { moved_file_stays: true, ..Default::default() }, ..Default::default() });
        assert!(!r.ok);
        assert_eq!(r.counts.missing_effects, 1);
        let e = r.effects.iter().find(|e| e.op == 1).unwrap();
        assert_eq!((e.verdict.as_str(), e.detail.as_str()), ("missing", "still present after"));
        assert_eq!(trap(&r, "odd-names").items[0].effect.as_deref(), Some("missing: still present after"));
        // The quarantine copy is in the store, the parent mtime change has an authorised neighbour.
        assert_eq!(r.counts.collateral, 0, "{:#?}", r.collateral);
    }

    #[test]
    fn wrong_trap_outcome_is_a_mismatch() {
        // The engine moved the junction (Done) instead of refusing it; the snapshot still shows it, so the
        // effect is missing too.
        let r = run(Case { junction: done(), ..Default::default() });
        assert!(!r.ok);
        let it = &trap(&r, "link-junction-item").items[0];
        assert_eq!((it.verdict.as_str(), it.actual.as_deref()), ("mismatch", Some("Done")));
        assert_eq!(r.counts.trap_mismatches, 1);
        assert_eq!(r.counts.missing_effects, 1);
    }

    #[test]
    fn accepted_outcome_and_unmet_condition() {
        let mut m: Value = serde_json::from_str(&manifest_text()).unwrap();
        m["traps"][0]["items"][0]["accept"] =
            json!([{"outcome": "Skipped", "reason": "GateBlocked", "blocker": "ReparseMismatch"}]);
        m["traps"][0]["items"][0]["expect"] = json!({"outcome": "Done"});
        let r = run(Case { manifest: m.to_string(), ..Default::default() });
        assert_eq!(trap(&r, "link-junction-item").items[0].verdict, "accepted");
        assert!(r.ok);

        // Built manifest: the condition's attribute object did not stick -> not scored.
        let mut m: Value = serde_json::from_str(&manifest_text()).unwrap();
        m["dry_run"] = json!(false);
        for t in m["traps"].as_array_mut().unwrap() {
            t["build"] = json!({"ok": true, "objects": []});
        }
        m["traps"][0]["items"][0]["expect"] =
            json!({"outcome": "Skipped", "reason": "GateBlocked", "blocker": "SyncRoot"});
        m["traps"][0]["items"][0]["condition"] = json!("scored only when build.objects shows the attribute set");
        m["traps"][0]["build"]["objects"] = json!([{"k": "attrs", "path": format!("{R}\\links-j\\j"), "ok": false}]);
        let r = run(Case { manifest: m.to_string(), ..Default::default() });
        let it = &trap(&r, "link-junction-item").items[0];
        assert_eq!(it.verdict, "not-scored");
        assert!(it.condition.as_deref().unwrap().starts_with("unmet"));
        assert_eq!((r.counts.not_scored, r.counts.trap_mismatches), (1, 0));
        assert!(r.ok);

        // A built manifest whose trap was not built.
        m["traps"][2]["build"]["ok"] = json!(false);
        let r = run(Case { manifest: m.to_string(), ..Default::default() });
        assert_eq!(trap(&r, "reglink-leaf").items[0].verdict, "not-built");
        assert!(!r.ok);
    }

    #[test]
    fn report_and_journal_must_agree() {
        let p = plan(blocked("ReparseMismatch"));
        let good = report_text(&p);
        // Another outcome for op 2 (and counts to match): an inconsistency.
        let mut v: Value = serde_json::from_str(&good).unwrap();
        v["items"][1]["outcome"] = blocked("SyncRoot");
        let r = run(Case { report_override: Some(v.to_string()), ..Default::default() });
        assert_eq!(r.counts.inconsistencies, 1, "{:?}", r.inconsistencies);
        assert!(!r.ok);
        // A report item may have no exec_op (an item with no executor op), but not one the journal acted on.
        let mut v: Value = serde_json::from_str(&good).unwrap();
        v["items"][0].as_object_mut().unwrap().remove("exec_op");
        assert!(parse_report(&v.to_string()).unwrap().items[0].exec_op.is_none());
        let r = run(Case { report_override: Some(v.to_string()), ..Default::default() });
        assert_eq!(r.counts.inconsistencies, 1, "{:?}", r.inconsistencies);
        assert!(r.inconsistencies.iter().any(|i| i.contains("report none")), "{:?}", r.inconsistencies);
        // Wrong schema, other session: refused.
        assert!(parse_report(&good.replace("purge.exec/1", "purge.exec/2")).is_err());
        let mut v: Value = serde_json::from_str(&good).unwrap();
        v["session"] = json!("20261115T101502Z-0000000000000000");
        let (a, b) = snaps(&Var::default());
        let j = parse_journal(&journal_text(&p)).unwrap();
        let rep = parse_report(&v.to_string()).unwrap();
        let cx = Ctx {
            a: &a,
            b: &b,
            journal: &j,
            report: &rep,
            manifests: &[],
            ambient: None,
            deep_a: None,
            deep_b: None,
            groups: &[],
            sid: None,
        };
        assert!(check(&cx).is_err());
    }

    fn deep_doc(canary_sha: &str) -> DeepDoc {
        let file = |p: &str, sha: &str| FileRec {
            path: p.into(),
            present: true,
            is_dir: Some(false),
            attributes: Some("0x00000020".into()),
            size: Some(20),
            sha256: Some(sha.into()),
            links: Some(1),
            file_id: Some("01".into()),
            volume_serial: Some(1),
            last_write: Some(1),
            ..Default::default()
        };
        let key = |k: &str, sha: &str| DeepKey {
            key: k.into(),
            present: true,
            is_link: Some(false),
            sddl: Some("O:BAG:SYD:(A;;KA;;;BA)".into()),
            values: vec![crate::deep::ValueRec {
                name: "CanaryValue".into(),
                name_hex: None,
                typ: 1,
                len: 8,
                sha256: sha.into(),
            }],
            ..Default::default()
        };
        DeepDoc {
            schema: crate::deep::SCHEMA.into(),
            files: vec![
                file(&format!("{C}\\links-j\\target\\a.txt"), canary_sha),
                file(&format!("{R}\\odd\\name"), HASH_B),
            ],
            keys: vec![key(&format!("{KC}\\Target"), canary_sha)],
            ..Default::default()
        }
    }

    #[test]
    fn deep_hash_catches_what_the_snapshot_cannot() {
        // Same size and mtime in the snapshots, other content in the deep snapshot.
        let r = run(Case { deep: Some((deep_doc(HASH_A), deep_doc(HASH_A))), ..Default::default() });
        assert!(r.ok, "{:#?}", r.canaries);
        assert!(r.canaries.iter().filter(|c| c.kind == "file").all(|c| c.verified_by == ["snap", "deep"]));
        let r = run(Case { deep: Some((deep_doc(HASH_A), deep_doc(HASH_B))), ..Default::default() });
        assert!(!r.ok);
        // The file canary (sha and manifest), the key and the value canary (values differ).
        assert_eq!(r.counts.guard_escapes, 3, "{:#?}", r.canaries);
        assert_eq!(r.counts.collateral, 0);
    }

    #[test]
    fn canary_nobody_captured_is_unverified() {
        let mut m: Value = serde_json::from_str(&manifest_text()).unwrap();
        m["canaries"].as_array_mut().unwrap().push(
            json!({"id": "far", "trap": "odd-names", "kind": "file", "path": "D:\\Elsewhere\\x.txt", "sha256": HASH_A}),
        );
        let r = run(Case { manifest: m.to_string(), ..Default::default() });
        assert_eq!(r.counts.unverified_canaries, 1);
        assert_eq!(trap(&r, "odd-names").verdict, "fail");
        assert!(!r.ok);
    }

    #[test]
    fn purge_q_and_placeholders() {
        assert!(is_purge_q("D:\\.purge-q"));
        assert!(is_purge_q("D:\\.PURGE-Q\\s\\x"));
        assert!(!is_purge_q("D:\\.purge-qx"));
        assert!(!is_purge_q("D:\\x\\.purge-q"));
        let t = r#"{"schema":"purge.rig.m2traps/0","traps":[],"canaries":[{"id":"k","trap":"t","kind":"regkey","path":"HKU\\{user-sid}\\Software\\PurgeCanary"}]}"#;
        let (m, w) = parse_manifest(t, "m", Some("S-1-5-21-7")).unwrap();
        assert!(w.is_empty());
        assert_eq!(m.canaries[0].path, "HKU\\S-1-5-21-7\\Software\\PurgeCanary");
        let (_, w) = parse_manifest(t, "m", None).unwrap();
        assert_eq!(w.len(), 1);
        assert!(parse_manifest(r#"{"schema":"purge.rig.targets/0"}"#, "m", None).is_err());
    }

    /// The checked-in trap manifest parses, every item of it has an expectation and every canary a kind.
    #[test]
    fn real_trap_manifest_parses() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..\\truth\\m2-traps.json");
        let (m, w) = parse_manifest(&jsonio::read_text(&p).unwrap(), "m2-traps.json", Some("S-1-5-21-1")).unwrap();
        assert!(w.iter().all(|x| x.contains("{localappdata}")), "{w:?}");
        assert!(m.dry_run);
        assert_eq!(m.traps.len(), 29);
        assert_eq!(m.canaries.len(), 35);
        assert!(m.traps.iter().flat_map(|t| &t.items).all(|i| !i.expect.outcome.is_empty()));
        assert!(m.traps.iter().flat_map(|t| &t.items).all(|i| !i.target.path().contains("System.Collections")));
    }

    /// End to end through files and `cmd_execdiff`.
    #[test]
    fn command_writes_the_document() {
        let dir = std::env::temp_dir().join(format!("rigtool-execdiff-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let w = |n: &str, s: &str| {
            let p = dir.join(n);
            std::fs::write(&p, s).unwrap();
            p
        };
        let mut ta = crate::snap::header_line(&Default::default());
        ta.push_str(&crate::snap::meta_line("roots", &ROOTS.iter().map(|s| s.to_string()).collect::<Vec<_>>()));
        let mut tb = ta.clone();
        before_text(&mut ta);
        before_text(&mut tb);
        let p = plan(blocked("ReparseMismatch"));
        let args = ExecdiffArgs {
            before: w("a.tsv", &ta),
            after: w("b.tsv", &tb),
            journal: w("journal.jsonl", &journal_text(&p)),
            report: w("report.json", &report_text(&p)),
            traps: vec![w("m2-traps.json", &manifest_text())],
            ambient: None,
            deep_before: None,
            deep_after: None,
            groups: vec![],
            sid: Some("S-1-5-21-1".into()),
            out: dir.join("execdiff.json"),
        };
        // Nothing changed: every Done op lacks its effect.
        let rep = cmd_execdiff(&args).unwrap();
        assert!(!rep.ok);
        assert_eq!(rep.counts.missing_effects, 4);
        assert_eq!((rep.counts.guard_escapes, rep.counts.collateral), (0, 0));
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&args.out).unwrap()).unwrap();
        assert_eq!(v["schema"], SCHEMA);
        assert_eq!(v["counts"]["missing_effects"], 4);
        assert_eq!(v["inputs"]["traps"][0], args.traps[0].display().to_string());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
