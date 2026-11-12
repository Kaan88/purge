//! The inventory document, `purge.inventory/0`: every installed program the engine can see
//! (ENGINE_PLAN.md §4.1, §3.4 `purge-engine inventory --json`).
//!
//! There is exactly one [`InventoryEntry`] per Uninstall key. The engine never deduplicates or hides
//! entries; an entry carries the raw flags, and grouping into tabs is a policy of the UI. MSI products
//! that have no Uninstall key are listed separately in [`InventoryDoc::msi_only`].

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::schema_id;
use crate::{FileTime, ProgramId, View};

schema_id!(
    /// The `schema` field of an inventory document: always the literal string `purge.inventory/0`.
    /// Deserialising any other value fails.
    InventorySchema = "purge.inventory/0"
);

/// The values and facts of an Uninstall key that tabs and filters are built from, as found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct RawFlags {
    /// `SystemComponent` is set to 1.
    pub system_component: bool,
    /// The key has a non-empty `DisplayName`.
    pub has_display_name: bool,
    /// The key has a non-empty `UninstallString`.
    pub has_uninstall_string: bool,
    /// `ParentKeyName`, when present (the entry is an update or component of that key).
    pub parent_key: Option<String>,
    /// `ReleaseType`, when present (e.g. `Hotfix`, `Security Update`).
    pub release_type: Option<String>,
    /// `WindowsInstaller` is set to 1.
    pub windows_installer: bool,
}

/// The installer technology behind an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum InstallerKind {
    /// Windows Installer.
    Msi,
    /// Inno Setup.
    Inno,
    /// NSIS.
    Nsis,
    /// A WiX Burn bundle.
    Burn,
    /// Anything else, or not recognised.
    Unknown,
}

/// Whether an app is installed for the machine or for one user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum InstallScope {
    /// Machine-wide (an `HKLM` entry).
    Machine,
    /// For one user (an `HKU\<sid>` entry).
    User,
}

/// Who can write an entry's Uninstall key; decides where its uninstaller may run (§4.4) and how far its
/// values are trusted (Rule T, §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WritableBy {
    /// Administrators only.
    Admin,
    /// The user.
    User,
}

/// Where a hint about the install time was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum InstallTimeSource {
    /// The ARP `InstallDate` value (day precision).
    ArpInstallDate,
    /// The LastWriteTime of the Uninstall key.
    KeyLastWrite,
    /// The creation time of the install directory.
    InstallDirCreation,
    /// The creation time of the Inno uninstall log (`unins000.dat`).
    UninstallLogCreation,
    /// The MSI `InstallDate` property (day precision).
    MsiInstallDate,
}

/// One raw hint about when the app was installed. The hints are kept as found; choosing among them is the
/// consumer's job.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct InstallTimeEvidence {
    /// Where the hint was read from.
    pub source: InstallTimeSource,
    /// The time it gives. Day-precision sources give local midnight of that day.
    pub time: FileTime,
}

/// The installation context of an MSI product.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum MsiContext {
    /// Per-machine.
    Machine,
    /// Per-user, managed.
    UserManaged,
    /// Per-user, unmanaged.
    UserUnmanaged,
}

/// What Windows Installer knows about an entry's product.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct MsiInfo {
    /// The context the product is installed in.
    pub context: MsiContext,
    /// Path of the cached package (`LocalPackage`), when registered.
    pub local_package: Option<String>,
    /// The `InstallDate` property as text (`YYYYMMDD`), when present.
    pub install_date: Option<String>,
}

/// One installed program: one Uninstall key (§4.1 "Each entry carries").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InventoryEntry {
    /// The entry's stable id.
    pub program_id: ProgramId,
    /// Canonical path of the Uninstall key.
    pub key_path: String,
    /// SID of the user hive the key is in; `None` for `HKLM`.
    pub hive_sid: Option<String>,
    /// The registry view the key was read through.
    pub view: View,
    /// `DisplayName`; the key name when the entry has none.
    pub display_name: String,
    /// `DisplayVersion`.
    pub version: Option<String>,
    /// `Publisher`.
    pub publisher: Option<String>,
    /// The raw flags.
    pub flags: RawFlags,
    /// The installer technology.
    pub installer_kind: InstallerKind,
    /// Machine-wide or per-user.
    pub scope: InstallScope,
    /// MSI ProductCode, in registry GUID form `{…}`.
    pub product_code: Option<String>,
    /// MSI or Burn UpgradeCode.
    pub upgrade_code: Option<String>,
    /// Inno Setup AppId (the key name without `_is1`).
    pub inno_app_id: Option<String>,
    /// Who can write the Uninstall key.
    pub writable_by: WritableBy,
    /// `InstallLocation`, as written in the key.
    pub install_location: Option<String>,
    /// `UninstallString`, as written in the key.
    pub uninstall_string: Option<String>,
    /// `QuietUninstallString`, as written in the key.
    pub quiet_uninstall_string: Option<String>,
    /// `DisplayIcon`, as written in the key.
    pub display_icon: Option<String>,
    /// Raw hints about the install time.
    #[serde(default)]
    pub install_time_evidence: Vec<InstallTimeEvidence>,
    /// Windows Installer's record of the product, when the entry was merged with one by ProductCode.
    pub msi: Option<MsiInfo>,
}

/// An MSI product that Windows Installer lists but that has no Uninstall key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct MsiOnlyRow {
    /// ProductCode, in registry GUID form `{…}`.
    pub product_code: String,
    /// The context the product is installed in.
    pub context: MsiContext,
    /// SID of the user the product is installed for; `None` for the machine context.
    pub user_sid: Option<String>,
    /// `ProductName`.
    pub product_name: Option<String>,
    /// `VersionString`.
    pub version: Option<String>,
    /// `Publisher`.
    pub publisher: Option<String>,
    /// `InstallLocation`.
    pub install_location: Option<String>,
    /// Path of the cached package (`LocalPackage`).
    pub local_package: Option<String>,
    /// The `InstallDate` property as text (`YYYYMMDD`).
    pub install_date: Option<String>,
}

/// An inventory document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InventoryDoc {
    /// Always `purge.inventory/0`.
    pub schema: InventorySchema,
    /// One entry per Uninstall key.
    pub entries: Vec<InventoryEntry>,
    /// MSI products without an Uninstall key.
    #[serde(default)]
    pub msi_only: Vec<MsiOnlyRow>,
}

impl InventoryDoc {
    /// The entry with the given id.
    pub fn entry(&self, program_id: &ProgramId) -> Option<&InventoryEntry> {
        self.entries.iter().find(|e| &e.program_id == program_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn sample() -> Value {
        json!({
            "schema": "purge.inventory/0",
            "entries": [
                {
                    "program_id": "HKLM|64|Git_is1",
                    "key_path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Git_is1",
                    "hive_sid": null, "view": "K64", "display_name": "Git", "version": "2.47.0",
                    "publisher": "The Git Development Community",
                    "flags": {"system_component": false, "has_display_name": true,
                              "has_uninstall_string": true, "parent_key": null, "release_type": null,
                              "windows_installer": false},
                    "installer_kind": "Inno", "scope": "Machine", "product_code": null,
                    "upgrade_code": null, "inno_app_id": "Git", "writable_by": "admin",
                    "install_location": "C:\\Program Files\\Git\\",
                    "uninstall_string": "\"C:\\Program Files\\Git\\unins000.exe\"",
                    "quiet_uninstall_string": "\"C:\\Program Files\\Git\\unins000.exe\" /SILENT",
                    "display_icon": "C:\\Program Files\\Git\\mingw64\\share\\git\\git-for-windows.ico",
                    "install_time_evidence": [
                        {"source": "ArpInstallDate", "time": 133900000000000000u64},
                        {"source": "KeyLastWrite", "time": 133900000450000000u64},
                        {"source": "InstallDirCreation", "time": 133900000400000000u64},
                        {"source": "UninstallLogCreation", "time": 133900000440000000u64}
                    ],
                    "msi": null
                },
                {
                    "program_id": "HKU:S-1-5-21-1-2-3-1001|64|{90160000-008C-0000-1000-0000000FF1CE}",
                    "key_path": "HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{90160000-008C-0000-1000-0000000FF1CE}",
                    "hive_sid": "S-1-5-21-1-2-3-1001", "view": "K64",
                    "display_name": "{90160000-008C-0000-1000-0000000FF1CE}", "version": null,
                    "publisher": null,
                    "flags": {"system_component": true, "has_display_name": false,
                              "has_uninstall_string": false, "parent_key": "Office",
                              "release_type": "Hotfix", "windows_installer": true},
                    "installer_kind": "Msi", "scope": "User",
                    "product_code": "{90160000-008C-0000-1000-0000000FF1CE}",
                    "upgrade_code": "{11111111-2222-3333-4444-555555555555}", "inno_app_id": null,
                    "writable_by": "user", "install_location": null, "uninstall_string": null,
                    "quiet_uninstall_string": null, "display_icon": null,
                    "install_time_evidence": [{"source": "MsiInstallDate", "time": 133900000000000000u64}],
                    "msi": {"context": "UserUnmanaged",
                            "local_package": "C:\\Windows\\Installer\\1a2b3c.msi",
                            "install_date": "20261112"}
                }
            ],
            "msi_only": [{
                "product_code": "{AAAAAAAA-0000-0000-0000-000000000001}", "context": "Machine",
                "user_sid": null, "product_name": "Hidden Runtime", "version": "1.0.0",
                "publisher": "Vendor", "install_location": null,
                "local_package": "C:\\Windows\\Installer\\ffff.msi", "install_date": "20260101"
            }]
        })
    }

    #[test]
    fn inventory_round_trips() {
        let v = sample();
        let doc: InventoryDoc = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(doc.entries.len(), 2);
        assert_eq!(doc.entries[0].installer_kind, InstallerKind::Inno);
        assert_eq!(doc.entries[1].writable_by, WritableBy::User);
        assert!(!doc.entries[1].flags.has_display_name);
        assert_eq!(serde_json::to_value(&doc).unwrap(), v);
        // The id and the key path agree.
        for e in &doc.entries {
            assert_eq!(e.program_id.key_path(), e.key_path);
            assert_eq!(e.program_id.hive_sid(), e.hive_sid.as_deref());
            assert_eq!(e.program_id.view(), e.view);
        }
        let id: ProgramId = "HKLM|64|Git_is1".parse().unwrap();
        assert_eq!(doc.entry(&id).unwrap().display_name, "Git");
        assert!(doc.entry(&"HKLM|32|Git_is1".parse().unwrap()).is_none());
    }

    #[test]
    fn unknown_schema_is_rejected() {
        for schema in ["purge.inventory/1", "purge.plan/0", "purge.run/0"] {
            let mut v = sample();
            v["schema"] = json!(schema);
            assert!(
                serde_json::from_value::<InventoryDoc>(v).is_err(),
                "{schema}"
            );
        }
    }

    #[test]
    fn every_enum_value_round_trips() {
        fn all<T: Serialize + for<'de> Deserialize<'de>>(names: &[&str]) {
            for name in names {
                let t: T = serde_json::from_value(json!(name)).unwrap();
                assert_eq!(serde_json::to_value(&t).unwrap(), json!(name));
            }
        }
        all::<InstallerKind>(&["Msi", "Inno", "Nsis", "Burn", "Unknown"]);
        all::<InstallScope>(&["Machine", "User"]);
        all::<WritableBy>(&["admin", "user"]);
        all::<MsiContext>(&["Machine", "UserManaged", "UserUnmanaged"]);
        all::<InstallTimeSource>(&[
            "ArpInstallDate",
            "KeyLastWrite",
            "InstallDirCreation",
            "UninstallLogCreation",
            "MsiInstallDate",
        ]);
    }

    #[test]
    fn json_schema_is_generated() {
        let text = serde_json::to_string(&schemars::schema_for!(InventoryDoc)).unwrap();
        assert!(text.contains(r#""const":"purge.inventory/0""#), "{text}");
        for name in [
            "system_component",
            "quiet_uninstall_string",
            "install_time_evidence",
            "UninstallLogCreation",
            "msi_only",
            "UserUnmanaged",
            "writable_by",
        ] {
            assert!(text.contains(name), "schema lacks {name}");
        }
    }
}
