//! The run document, `purge.run/0`: what happened when the engine ran an app's uninstaller
//! (ENGINE_PLAN.md §3.4 `purge-engine uninstall … -o run.json`, §4.4).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::schema_id;
use crate::{FileTime, ProgramId};

schema_id!(
    /// The `schema` field of a run document: always the literal string `purge.run/0`. Deserialising any
    /// other value fails.
    RunSchema = "purge.run/0"
);

/// How the uninstaller ended (§4.4 "Exit codes").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum RunOutcome {
    /// Exit code 0. A success *candidate*: [`VerifyGone`] decides whether the app is really gone.
    Success,
    /// Exit code 1605: the product was not installed any more.
    AlreadyGone,
    /// Exit code 1641 or 3010: success, a restart is needed.
    SuccessReboot,
    /// Exit code 1602: the user cancelled.
    Cancelled,
    /// Any other exit code, or the command could not be started.
    Failed,
    /// The wait for the process tree gave up.
    TimedOut,
}

impl RunOutcome {
    /// The outcome an exit code stands for (§4.4). [`RunOutcome::TimedOut`] is never returned: it is the
    /// runner's own finding, not an exit code.
    pub fn from_exit_code(code: u32) -> Self {
        match code {
            0 => RunOutcome::Success,
            1605 => RunOutcome::AlreadyGone,
            1641 | 3010 => RunOutcome::SuccessReboot,
            1602 => RunOutcome::Cancelled,
            _ => RunOutcome::Failed,
        }
    }

    /// Whether the uninstaller itself reported the app as removed (before verify-gone).
    pub fn is_success(self) -> bool {
        matches!(
            self,
            RunOutcome::Success | RunOutcome::AlreadyGone | RunOutcome::SuccessReboot
        )
    }
}

/// The verify-gone check that gates the Safe band (§4.4, §5.8.3).
///
/// Each part is `true` only when positively established; "could not tell" is `false`.
///
/// `passed` is stored for readers of the document, but it is never trusted on its own: reading a document
/// clears it unless all three parts hold, and consumers ask [`VerifyGone::is_passed`], which checks the
/// parts again. An inconsistent `{"arp_gone": false, …, "passed": true}` therefore cannot unlock the Safe
/// band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, JsonSchema)]
pub struct VerifyGone {
    /// The ARP entry is gone.
    pub arp_gone: bool,
    /// `MsiQueryProductState` is UNKNOWN in every context (`true` when the entry has no ProductCode).
    pub msi_unknown_all_ctx: bool,
    /// The main exes of the fingerprint are gone.
    pub main_exes_gone: bool,
    /// All three hold. When `false` the scan runs under the forced-mode rules.
    pub passed: bool,
}

impl VerifyGone {
    /// Builds the result from its three parts; `passed` is their conjunction.
    pub fn new(arp_gone: bool, msi_unknown_all_ctx: bool, main_exes_gone: bool) -> Self {
        Self {
            arp_gone,
            msi_unknown_all_ctx,
            main_exes_gone,
            passed: arp_gone && msi_unknown_all_ctx && main_exes_gone,
        }
    }

    /// Whether the app is verified gone: `passed` is set **and** all three parts hold. Use this instead of
    /// the `passed` field, which a struct literal can set inconsistently.
    pub fn is_passed(&self) -> bool {
        self.passed && self.arp_gone && self.msi_unknown_all_ctx && self.main_exes_gone
    }
}

/// Field-for-field copy of [`VerifyGone`], used to bring `passed` in line with the parts when reading.
#[derive(Deserialize)]
#[serde(rename = "VerifyGone")]
struct RawVerifyGone {
    arp_gone: bool,
    msi_unknown_all_ctx: bool,
    main_exes_gone: bool,
    passed: bool,
}

impl<'de> Deserialize<'de> for VerifyGone {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawVerifyGone::deserialize(deserializer)?;
        let mut verify = VerifyGone::new(raw.arp_gone, raw.msi_unknown_all_ctx, raw.main_exes_gone);
        // Fail safe in both directions: a stored `false` stays `false`.
        verify.passed &= raw.passed;
        Ok(verify)
    }
}

/// A process seen during the uninstall: one of the uninstaller's tree, or one still running under the
/// app's roots.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ProcessSeen {
    /// Process id.
    pub pid: u32,
    /// Image file name, e.g. `unins000.exe`.
    pub name: String,
    /// Full image path, when it could be read.
    pub path: Option<String>,
    /// Start time, when it could be read. With the pid it identifies the process uniquely.
    pub start: Option<FileTime>,
}

/// A run document: the record of one uninstall run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunDoc {
    /// Always `purge.run/0`.
    pub schema: RunSchema,
    /// The entry that was uninstalled.
    pub program_id: ProgramId,
    /// The exact command line that was run.
    pub cmd: String,
    /// Authenticode signer of the uninstaller, when it is signed.
    pub signer: Option<String>,
    /// When the command was started.
    pub t_start: FileTime,
    /// When the wait ended (tree exited, MSI idle, ARP entry gone or given up).
    pub t_end: FileTime,
    /// Exit code of the root process; `None` when it could not be started or was not awaited to its end.
    pub exit_code: Option<u32>,
    /// How the run ended.
    pub outcome: RunOutcome,
    /// The verify-gone result after the run.
    pub verify_gone: VerifyGone,
    /// Processes seen during the run.
    #[serde(default)]
    pub processes: Vec<ProcessSeen>,
    /// Other ARP entries that disappeared during the run (co-removed products).
    #[serde(default)]
    pub co_removed: Vec<ProgramId>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn sample() -> Value {
        json!({
            "schema": "purge.run/0", "program_id": "HKLM|64|Git_is1",
            "cmd": "\"C:\\Program Files\\Git\\unins000.exe\" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
            "signer": "Johannes Schindelin", "t_start": 134000000000000000u64,
            "t_end": 134000000450000000u64, "exit_code": 0, "outcome": "Success",
            "verify_gone": {"arp_gone": true, "msi_unknown_all_ctx": true, "main_exes_gone": true,
                            "passed": true},
            "processes": [{"pid": 4242, "name": "unins000.exe",
                           "path": "C:\\Program Files\\Git\\unins000.exe", "start": 134000000000000001u64},
                          {"pid": 4300, "name": "_iu14D2N.tmp", "path": null, "start": null}],
            "co_removed": ["HKLM|32|Mozilla Maintenance Service"]
        })
    }

    #[test]
    fn run_doc_round_trips() {
        let v = sample();
        let doc: RunDoc = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(doc.outcome, RunOutcome::Success);
        assert_eq!(doc.processes.len(), 2);
        assert_eq!(doc.co_removed[0].key_name(), "Mozilla Maintenance Service");
        assert_eq!(serde_json::to_value(&doc).unwrap(), v);
    }

    #[test]
    fn unknown_schema_is_rejected() {
        for schema in ["purge.run/1", "purge.plan/0", "purge.fp/0", ""] {
            let mut v = sample();
            v["schema"] = json!(schema);
            assert!(serde_json::from_value::<RunDoc>(v).is_err(), "{schema}");
        }
        let mut v = sample();
        v.as_object_mut().unwrap().remove("schema");
        assert!(serde_json::from_value::<RunDoc>(v).is_err());
    }

    #[test]
    fn exit_codes_map_to_outcomes() {
        for (code, outcome) in [
            (0, RunOutcome::Success),
            (1605, RunOutcome::AlreadyGone),
            (1641, RunOutcome::SuccessReboot),
            (3010, RunOutcome::SuccessReboot),
            (1602, RunOutcome::Cancelled),
            (1, RunOutcome::Failed),
            (1603, RunOutcome::Failed),
            (0xC000_0005, RunOutcome::Failed),
        ] {
            assert_eq!(RunOutcome::from_exit_code(code), outcome, "{code}");
        }
        assert!(RunOutcome::Success.is_success() && RunOutcome::SuccessReboot.is_success());
        assert!(RunOutcome::AlreadyGone.is_success());
        for o in [
            RunOutcome::Cancelled,
            RunOutcome::Failed,
            RunOutcome::TimedOut,
        ] {
            assert!(!o.is_success());
        }
        for name in [
            "Success",
            "AlreadyGone",
            "SuccessReboot",
            "Cancelled",
            "Failed",
            "TimedOut",
        ] {
            let o: RunOutcome = serde_json::from_value(json!(name)).unwrap();
            assert_eq!(serde_json::to_value(o).unwrap(), json!(name));
        }
    }

    #[test]
    fn verify_gone_passes_only_when_all_parts_hold() {
        assert!(VerifyGone::new(true, true, true).passed);
        assert!(!VerifyGone::new(false, true, true).passed);
        assert!(!VerifyGone::new(true, false, true).passed);
        assert!(!VerifyGone::new(true, true, false).passed);
        assert!(VerifyGone::new(true, true, true).is_passed());
        // A struct literal that claims `passed` against its parts does not pass.
        let lie = VerifyGone {
            arp_gone: false,
            msi_unknown_all_ctx: true,
            main_exes_gone: true,
            passed: true,
        };
        assert!(!lie.is_passed());
    }

    /// A document cannot claim `passed` while a part is false; a stored `false` is kept.
    #[test]
    fn reading_verify_gone_never_trusts_an_inconsistent_passed() {
        for (arp, msi, exes) in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
            (false, false, false),
        ] {
            let v: VerifyGone = serde_json::from_value(json!({
                "arp_gone": arp, "msi_unknown_all_ctx": msi, "main_exes_gone": exes, "passed": true
            }))
            .unwrap();
            assert!(!v.passed && !v.is_passed(), "{arp} {msi} {exes}");
        }
        let v: VerifyGone = serde_json::from_value(json!({
            "arp_gone": true, "msi_unknown_all_ctx": true, "main_exes_gone": true, "passed": false
        }))
        .unwrap();
        assert!(!v.passed && !v.is_passed());
        let v: VerifyGone = serde_json::from_value(json!({
            "arp_gone": true, "msi_unknown_all_ctx": true, "main_exes_gone": true, "passed": true
        }))
        .unwrap();
        assert!(v.is_passed());
        // Every field is required: a missing part is an error, not `false`-or-`true` by default.
        assert!(
            serde_json::from_value::<VerifyGone>(json!({"arp_gone": true, "passed": true}))
                .is_err()
        );
        // The same holds inside a run document.
        let mut doc = sample();
        doc["verify_gone"]["main_exes_gone"] = json!(false);
        let doc: RunDoc = serde_json::from_value(doc).unwrap();
        assert!(!doc.verify_gone.is_passed());
    }

    #[test]
    fn json_schema_is_generated() {
        let text = serde_json::to_string(&schemars::schema_for!(RunDoc)).unwrap();
        assert!(text.contains(r#""const":"purge.run/0""#), "{text}");
        for name in [
            "SuccessReboot",
            "TimedOut",
            "msi_unknown_all_ctx",
            "co_removed",
            "ProgramId",
        ] {
            assert!(text.contains(name), "schema lacks {name}");
        }
    }
}
