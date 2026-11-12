//! The fingerprint document, `purge.fp/0`: everything the engine learned about one app **before** its
//! uninstaller ran (ENGINE_PLAN.md §5.2 "Fingerprint", §3.4 `purge-engine harvest … -o fp.json`).
//!
//! The harvest writes it; the uninstall step adds the time window, the verify-gone result and the
//! co-removed products; the scan reads it and needs no other knowledge of the app. It is self-contained on
//! purpose: after the uninstall the registry and the install directory can no longer be asked.
//!
//! The M1a fingerprint holds what the M1a harvesters produce. MSI rows, Burn children, services, tasks and
//! firewall rules join it with their milestones; fields added later default to empty when absent.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::schema_id;
use crate::{AppRef, FileTime, ProgramId, Root, SourceId, Target, VerifyGone, View};

schema_id!(
    /// The `schema` field of a fingerprint document: always the literal string `purge.fp/0`.
    /// Deserialising any other value fails.
    FingerprintSchema = "purge.fp/0"
);

/// The app's resolved identity (§5.4), stored so that the scan matches names exactly as the harvest did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct IdentitySnapshot {
    /// Every name the app goes by (DisplayName, Inno AppName, ARP key name, main exe names, VersionInfo
    /// ProductName and FileDescription), as found.
    pub names: Vec<String>,
    /// Every vendor name (Publisher, signer CN, VersionInfo CompanyName, URL host, KB aliases), as found.
    pub vendors: Vec<String>,
    /// The significant name tokens left by the tokenizer (normalised, stopwords and generic and common
    /// tokens dropped). Empty means name-based evidence is disabled for this app.
    pub tokens: Vec<String>,
    /// The vendor is a mega-vendor (`kb/mega-vendors.json`): a vendor-only match weighs 0 and name matching
    /// needs two distinctive tokens.
    pub mega_vendor: bool,
}

/// One executable (or DLL) of the app, found under a root at harvest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ExeFile {
    /// Canonical absolute path.
    pub path: String,
    /// One of the app's main exes: verify-gone requires these to be gone.
    pub main: bool,
}

/// A file the installer's record declares outside every root (e.g. `py.exe` in `C:\Windows`). Used only to
/// recognise dangling references; never a removal target by itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct AppFileOutsideRoot {
    /// Canonical absolute path.
    pub path: String,
    /// The record that declares it.
    pub source: SourceId,
}

/// A Run-key value that starts something inside the app's roots.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct RunEntry {
    /// Canonical path of the Run key.
    pub key: String,
    /// The value's name.
    pub name: String,
    /// The value's data (the command line).
    pub data: String,
}

/// The registry and package identifiers that are the app's own (§5.4 "Anchors").
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Anchors {
    /// The ProgID set P: Classes keys whose `shell\*\command` targets the roots and that nothing outside
    /// the app references. ProgIDs that existed before and were only modified are not in P.
    #[serde(default)]
    pub progids: Vec<String>,
    /// CLSIDs whose server lies in the roots, in `{…}` form.
    #[serde(default)]
    pub clsids: Vec<String>,
    /// AppIDs, in `{…}` form.
    #[serde(default)]
    pub appids: Vec<String>,
    /// Type library ids, in `{…}` form.
    #[serde(default)]
    pub typelibs: Vec<String>,
    /// AppUserModelIDs.
    #[serde(default)]
    pub aumids: Vec<String>,
    /// Package family names of linked AppX/MSIX packages.
    #[serde(default)]
    pub package_families: Vec<String>,
    /// Package full names of linked AppX/MSIX packages.
    #[serde(default)]
    pub package_full_names: Vec<String>,
    /// Run entries pointing into the roots.
    #[serde(default)]
    pub run_entries: Vec<RunEntry>,
}

/// A GUID or long hex token taken from the app's own anchors (§5.3 `HarvestedToken`), e.g. Firefox's
/// install hash or an Inno AppId GUID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct HarvestedToken {
    /// The token text, as found.
    pub token: String,
    /// The anchor it was taken from.
    pub source: SourceId,
}

/// What an Inno Setup uninstall-log record tells the uninstaller to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum InnoRecordKind {
    /// Delete a file.
    DeleteFile,
    /// Delete a directory, or files by pattern.
    DeleteDirOrFiles,
    /// Delete a Start Menu group or shortcut.
    DeleteGroupOrItem,
    /// Delete an entry of an INI file.
    IniDeleteEntry,
    /// Delete a section of an INI file.
    IniDeleteSection,
    /// Delete a registry key with its subtree.
    RegDeleteEntireKey,
    /// Clear a registry value.
    RegClearValue,
    /// Delete a registry key if it is empty.
    RegDeleteKeyIfEmpty,
    /// Delete a registry value.
    RegDeleteValue,
    /// Decrement a shared-file count.
    DecrementSharedCount,
}

/// One decoded and normalised record of an Inno Setup uninstall log (`unins*.dat`, §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct InnoRecord {
    /// What the record does.
    pub kind: InnoRecordKind,
    /// What it acts on, with a canonical path. A registry record under `HKCU` keeps the root `HKCU\…`
    /// while [`InnoRecord::user_hive`] is set and the record is not yet bound to a user.
    pub target: Target,
    /// The registry view of a registry record (`ExtraData & 0x01000000` = 64-bit); `None` for files.
    pub view: Option<View>,
    /// The record addresses the installing user's hive (`HKCU`). The harvest binds it to that user's SID,
    /// rewrites the target to `HKU\<sid>\…` and leaves this flag set.
    #[serde(default)]
    pub user_hive: bool,
    /// The log says the item existed before the install (`ExistedBeforeInstall`).
    pub existed_before: bool,
    /// The log marks the file as shared (`SharedFile`).
    pub shared: bool,
    /// The record shows that the installer created the key ([`InnoRecordKind::RegDeleteEntireKey`] or
    /// [`InnoRecordKind::RegDeleteKeyIfEmpty`] on exactly this key): Key scope. All other records give
    /// Value or Path scope only.
    pub key_create: bool,
}

/// Where in a value a reference was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum RefCarrier {
    /// The value's name.
    ValueName,
    /// `REG_SZ` or `REG_EXPAND_SZ` data.
    Data,
    /// One segment of a `REG_MULTI_SZ`, or of a `;`-separated string.
    Segment,
    /// A UTF-16 string inside `REG_BINARY` data.
    Binary,
}

/// What kind of anchor a reference matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum AnchorKind {
    /// A root directory (the reference points at or under it).
    Root,
    /// A file of the exe set.
    Exe,
    /// A ProgID of P.
    ProgId,
    /// A CLSID.
    Clsid,
    /// An AppUserModelID.
    Aumid,
    /// A harvested token.
    Token,
}

/// The anchor a reference matched.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct AnchorRef {
    /// Its kind.
    pub kind: AnchorKind,
    /// The anchor's text (the root path, the ProgID, the token…).
    pub text: String,
}

/// One entry of the pre-uninstall reference snapshot (§5.5): a registry value that referenced one of the
/// app's anchors while the app was still installed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct RefSnapEntry {
    /// The referencing value: a [`Target::RegValue`], or a [`Target::RegMultiSzSegment`] when one segment
    /// of a list-like value holds the reference.
    pub target: Target,
    /// Where in the value the reference was found.
    pub carrier: RefCarrier,
    /// The anchor it matched.
    pub anchor: AnchorRef,
    /// Number of values the value's key had at harvest.
    pub parent_values: u32,
    /// Number of subkeys the value's key had at harvest.
    pub parent_subkeys: u32,
    /// Hash of the value's data at harvest (lower-case hex), when it was read.
    pub data_hash: Option<String>,
}

/// A value inside a harvested subtree.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct SubtreeValue {
    /// Path of the value's key relative to the subtree's key; empty for the key itself.
    pub subkey: String,
    /// Value name; empty for the default value.
    pub name: String,
    /// Hash of type and data (lower-case hex).
    pub hash: String,
}

/// The state of one registry key's subtree at harvest (§5.2 "subtree baselines"), from which
/// `ProvenOwnedSkeleton` is later derived.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct SubtreeBaseline {
    /// Canonical path of the key.
    pub key: String,
    /// Every value in the subtree.
    #[serde(default)]
    pub values: Vec<SubtreeValue>,
    /// Every subkey in the subtree, as a path relative to the key.
    #[serde(default)]
    pub subkeys: Vec<String>,
    /// The key's LastWriteTime.
    pub lwt: FileTime,
    /// The key is owned by TrustedInstaller or carries a TrustedInstaller ACE.
    pub ti_owned: bool,
    /// Every value and subkey in the subtree was attributed to the app with Tier A at harvest (a reference
    /// snapshot hit, an installer record, or a name in P).
    pub fully_attributed: bool,
}

/// A value a vendor left to remember the previous default of an extension (e.g. `Notepad++_backup`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct VendorBackup {
    /// The backup value's name.
    pub name: String,
    /// Its data: the previous default.
    pub data: String,
}

/// The pre-uninstall state of one file extension the app registered with (§5.7.1 "Harvest").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ExtJournalEntry {
    /// The extension, with its dot, e.g. `.txt`.
    pub ext: String,
    /// Canonical path of the extension's Classes key.
    pub key: String,
    /// `OpenWithProgids` value names that are in P.
    #[serde(default)]
    pub openwith_ours: Vec<String>,
    /// `OpenWithProgids` value names that are not ours.
    #[serde(default)]
    pub openwith_others: Vec<String>,
    /// Number of direct subkeys of the extension's key.
    pub subkey_count: u32,
    /// The extension's default value (its ProgID), when set.
    pub default: Option<String>,
    /// The default the extension had before the app took it, when known.
    pub previous_default: Option<String>,
    /// Names of the key's other values (neither the default nor a vendor backup).
    #[serde(default)]
    pub other_values: Vec<String>,
    /// Names of the key's subkeys other than `OpenWithProgids`.
    #[serde(default)]
    pub other_subkeys: Vec<String>,
    /// The key is owned by TrustedInstaller or carries a TrustedInstaller ACE.
    pub ti_owned: bool,
    /// The vendor's backup of the previous default, when present.
    pub vendor_backup: Option<VendorBackup>,
    /// Canonical path of the user's `Explorer\FileExts\<ext>` key, when it references P.
    pub file_exts_key: Option<String>,
    /// Names of `ApplicationAssociationToasts` values for this extension and a ProgID of P.
    #[serde(default)]
    pub toast_values: Vec<String>,
}

/// Another ARP entry that disappeared during the same uninstall (§5.2 "co-removed products"), e.g. the
/// Mozilla Maintenance Service next to Firefox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CoRemovedProduct {
    /// The entry that disappeared.
    pub app: AppRef,
    /// Its own fingerprint, harvested before the uninstall. `None` when it was not pre-harvested; its
    /// leftovers can then not be attributed through it.
    pub fingerprint: Option<Box<Fingerprint>>,
}

/// The Windows the fingerprint was taken on; selects the (edition, build) baseline.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct OsInfo {
    /// `EditionID`, e.g. `Professional`, `EnterpriseSEval`.
    pub edition: String,
    /// Build number, e.g. `26100`.
    pub build: u32,
    /// Update build revision, e.g. `1742`.
    pub ubr: u32,
}

impl OsInfo {
    /// The baseline name for this Windows: `<edition>-<build>.<ubr>`, as in `kb/baselines`.
    pub fn baseline_name(&self) -> String {
        format!("{}-{}.{}", self.edition, self.build, self.ubr)
    }
}

/// The time window `[install_time, t_start, t_end]` of the session (§5.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct TimeWindow {
    /// When the app was installed, as far as the inventory's hints tell.
    pub install_time: Option<FileTime>,
    /// When the uninstaller was started; `None` until it ran.
    pub t_start: Option<FileTime>,
    /// When the uninstall ended; `None` until it ran.
    pub t_end: Option<FileTime>,
}

/// A fingerprint document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Fingerprint {
    /// Always `purge.fp/0`.
    pub schema: FingerprintSchema,
    /// The app.
    pub app: AppRef,
    /// Its identity.
    pub identity: IdentitySnapshot,
    /// Its validated roots.
    #[serde(default)]
    pub roots: Vec<Root>,
    /// Its exe/dll set.
    #[serde(default)]
    pub exes: Vec<ExeFile>,
    /// Files its installer declares outside the roots.
    #[serde(default)]
    pub outside_root_files: Vec<AppFileOutsideRoot>,
    /// Its registry and package anchors.
    #[serde(default)]
    pub anchors: Anchors,
    /// Its harvested tokens.
    #[serde(default)]
    pub tokens: Vec<HarvestedToken>,
    /// The records of its Inno Setup uninstall log; empty when it has none or the log was not readable.
    #[serde(default)]
    pub inno: Vec<InnoRecord>,
    /// The reference snapshot.
    #[serde(default)]
    pub ref_snapshot: Vec<RefSnapEntry>,
    /// The subtree baselines of harvested keys.
    #[serde(default)]
    pub subtrees: Vec<SubtreeBaseline>,
    /// The file-association journal.
    #[serde(default)]
    pub ext_journal: Vec<ExtJournalEntry>,
    /// Products removed together with the app; filled by the uninstall step.
    #[serde(default)]
    pub co_removed: Vec<CoRemovedProduct>,
    /// The Windows it was taken on.
    pub os: OsInfo,
    /// SID of the interactive user the per-user parts were read for.
    pub user_sid: String,
    /// The session's time window.
    #[serde(default)]
    pub window: TimeWindow,
    /// The verify-gone result; `None` until the uninstall ran.
    pub verify_gone: Option<VerifyGone>,
    /// Things the harvest could not do (an unreadable log, an unknown log version…), for the report.
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl Fingerprint {
    /// The app's inventory id.
    pub fn program_id(&self) -> &ProgramId {
        &self.app.program_id
    }

    /// The main exes, which verify-gone checks.
    pub fn main_exes(&self) -> impl Iterator<Item = &ExeFile> {
        self.exes.iter().filter(|e| e.main)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RootKind, SourceTrust};
    use serde_json::{Value, json};

    const SID: &str = "S-1-5-21-1-2-3-1001";

    /// A fingerprint with every field and every collection populated.
    fn sample() -> Value {
        json!({
            "schema": "purge.fp/0",
            "app": {"program_id": "HKLM|64|{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1",
                    "display_name": "Microsoft Visual Studio Code"},
            "identity": {"names": ["Microsoft Visual Studio Code", "Code.exe"],
                         "vendors": ["Microsoft Corporation"], "tokens": ["visual", "studio", "code"],
                         "mega_vendor": true},
            "roots": [{"path": "C:\\Program Files\\Microsoft VS Code", "kind": "InstallRoot",
                       "source": "InnoApp", "trust": "AdminOnly", "volume_serial": 2864434397u32,
                       "parent_existed": true}],
            "exes": [{"path": "C:\\Program Files\\Microsoft VS Code\\Code.exe", "main": true},
                     {"path": "C:\\Program Files\\Microsoft VS Code\\ffmpeg.dll", "main": false}],
            "outside_root_files": [{"path": "C:\\Windows\\py.exe", "source": "inno:unins000.dat"}],
            "anchors": {
                "progids": ["VSCode.txt", "VSCodeSourceFile"],
                "clsids": ["{0632BBFB-D195-4972-B458-53ADEB984588}"],
                "appids": ["{11111111-0000-0000-0000-000000000001}"],
                "typelibs": ["{22222222-0000-0000-0000-000000000002}"],
                "aumids": ["Microsoft.VisualStudioCode"],
                "package_families": ["Microsoft.VSCode_8wekyb3d8bbwe"],
                "package_full_names": ["Microsoft.VSCode_1.95.0.0_x64__8wekyb3d8bbwe"],
                "run_entries": [{"key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                                 "name": "Code", "data": "\"C:\\Program Files\\Microsoft VS Code\\Code.exe\""}]
            },
            "tokens": [{"token": "771FD6B0-FA20-440A-A002-3B3BAC16DC50", "source": "arp:key"}],
            "inno": [
                {"kind": "RegDeleteEntireKey",
                 "target": {"type": "RegKey", "path": "HKLM\\SOFTWARE\\Classes\\VSCode.txt"},
                 "view": "K64", "user_hive": false, "existed_before": false, "shared": false,
                 "key_create": true},
                {"kind": "RegDeleteValue",
                 "target": {"type": "RegValue", "path": "HKCU\\Software\\Classes\\.txt\\OpenWithProgids",
                            "name": "VSCode.txt"},
                 "view": "K64", "user_hive": true, "existed_before": false, "shared": false,
                 "key_create": false},
                {"kind": "DeleteFile",
                 "target": {"type": "Path", "path": "C:\\Program Files\\Microsoft VS Code\\Code.exe"},
                 "view": null, "user_hive": false, "existed_before": true, "shared": true,
                 "key_create": false}
            ],
            "ref_snapshot": [
                {"target": {"type": "RegValue", "path": "HKLM\\SOFTWARE\\Classes\\.txt\\OpenWithProgids",
                            "name": "VSCode.txt"},
                 "carrier": "ValueName", "anchor": {"kind": "ProgId", "text": "VSCode.txt"},
                 "parent_values": 1, "parent_subkeys": 0, "data_hash": null},
                {"target": {"type": "RegMultiSzSegment",
                            "path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                            "name": "Path", "segment": "C:\\Program Files\\Microsoft VS Code\\bin",
                            "index": 7},
                 "carrier": "Segment",
                 "anchor": {"kind": "Root", "text": "C:\\Program Files\\Microsoft VS Code"},
                 "parent_values": 14, "parent_subkeys": 0, "data_hash": "9f86d081884c7d65"}
            ],
            "subtrees": [{
                "key": "HKLM\\SOFTWARE\\Classes\\.txt",
                "values": [{"subkey": "", "name": "", "hash": "aa11"},
                           {"subkey": "OpenWithProgids", "name": "VSCode.txt", "hash": "bb22"}],
                "subkeys": ["OpenWithProgids"], "lwt": 133900000450000000u64, "ti_owned": false,
                "fully_attributed": false
            }],
            "ext_journal": [{
                "ext": ".txt", "key": "HKLM\\SOFTWARE\\Classes\\.txt",
                "openwith_ours": ["VSCode.txt"], "openwith_others": ["txtfile"], "subkey_count": 2,
                "default": "txtfile", "previous_default": null, "other_values": ["Content Type"],
                "other_subkeys": ["PersistentHandler"], "ti_owned": true,
                "vendor_backup": {"name": "Notepad++_backup", "data": "txtfile"},
                "file_exts_key": format!("HKU\\{SID}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.txt"),
                "toast_values": ["VSCode.txt_.txt"]
            }],
            "co_removed": [
                {"app": {"program_id": "HKLM|32|Helper", "display_name": "Helper"}, "fingerprint": null},
                {"app": {"program_id": "HKLM|64|Other", "display_name": "Other"},
                 "fingerprint": minimal("HKLM|64|Other")}
            ],
            "os": {"edition": "EnterpriseSEval", "build": 26100, "ubr": 1742},
            "user_sid": SID,
            "window": {"install_time": 133900000400000000u64, "t_start": 134000000000000000u64,
                       "t_end": 134000000450000000u64},
            "verify_gone": {"arp_gone": true, "msi_unknown_all_ctx": true, "main_exes_gone": true,
                            "passed": true},
            "warnings": ["inno: log version 6400 is newer than supported"]
        })
    }

    /// A fingerprint as the harvest writes it for an app with nothing to find, in full form.
    fn minimal(program_id: &str) -> Value {
        json!({
            "schema": "purge.fp/0",
            "app": {"program_id": program_id, "display_name": "Other"},
            "identity": {"names": [], "vendors": [], "tokens": [], "mega_vendor": false},
            "roots": [], "exes": [], "outside_root_files": [],
            "anchors": {"progids": [], "clsids": [], "appids": [], "typelibs": [], "aumids": [],
                        "package_families": [], "package_full_names": [], "run_entries": []},
            "tokens": [], "inno": [], "ref_snapshot": [], "subtrees": [], "ext_journal": [],
            "co_removed": [],
            "os": {"edition": "Professional", "build": 26340, "ubr": 9882},
            "user_sid": SID,
            "window": {"install_time": null, "t_start": null, "t_end": null},
            "verify_gone": null, "warnings": []
        })
    }

    #[test]
    fn fingerprint_round_trips() {
        let v = sample();
        let fp: Fingerprint = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(fp.roots[0].kind, RootKind::InstallRoot);
        assert_eq!(fp.roots[0].trust, SourceTrust::AdminOnly);
        assert_eq!(fp.inno.len(), 3);
        assert!(fp.inno[0].key_create && fp.inno[1].user_hive && fp.inno[2].shared);
        assert_eq!(fp.ref_snapshot[1].carrier, RefCarrier::Segment);
        assert_eq!(fp.co_removed.len(), 2);
        assert!(fp.co_removed[1].fingerprint.is_some());
        assert_eq!(fp.os.baseline_name(), "EnterpriseSEval-26100.1742");
        assert_eq!(fp.program_id().view(), View::K64);
        assert_eq!(
            fp.main_exes().map(|e| e.path.as_str()).collect::<Vec<_>>(),
            [r"C:\Program Files\Microsoft VS Code\Code.exe"]
        );
        assert_eq!(serde_json::to_value(&fp).unwrap(), v);
        // And through text, as the CLI writes and reads it.
        let text = serde_json::to_string_pretty(&fp).unwrap();
        assert_eq!(serde_json::from_str::<Fingerprint>(&text).unwrap(), fp);
    }

    #[test]
    fn minimal_fingerprint_round_trips_and_optional_parts_default() {
        let v = minimal("HKLM|64|Other");
        let fp: Fingerprint = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(serde_json::to_value(&fp).unwrap(), v);
        assert_eq!(fp.window, TimeWindow::default());
        assert_eq!(fp.main_exes().count(), 0);

        // Collections that a later milestone adds, or that are simply empty, may be absent.
        let sparse = json!({
            "schema": "purge.fp/0",
            "app": {"program_id": "HKLM|64|Other", "display_name": "Other"},
            "identity": {"names": [], "vendors": [], "tokens": [], "mega_vendor": false},
            "os": {"edition": "Professional", "build": 26340, "ubr": 9882},
            "user_sid": SID
        });
        assert_eq!(serde_json::from_value::<Fingerprint>(sparse).unwrap(), fp);
    }

    #[test]
    fn unknown_schema_is_rejected() {
        for schema in ["purge.fp/1", "purge.plan/0", "purge.inventory/0", "fp"] {
            let mut v = sample();
            v["schema"] = json!(schema);
            assert!(
                serde_json::from_value::<Fingerprint>(v).is_err(),
                "{schema}"
            );
        }
        // Also inside a co-removed product's fingerprint.
        let mut v = sample();
        v["co_removed"][1]["fingerprint"]["schema"] = json!("purge.fp/9");
        assert!(serde_json::from_value::<Fingerprint>(v).is_err());
    }

    #[test]
    fn every_enum_value_round_trips() {
        fn all<T: Serialize + for<'de> Deserialize<'de>>(names: &[&str]) {
            for name in names {
                let t: T = serde_json::from_value(json!(name)).unwrap();
                assert_eq!(serde_json::to_value(&t).unwrap(), json!(name));
            }
        }
        all::<InnoRecordKind>(&[
            "DeleteFile",
            "DeleteDirOrFiles",
            "DeleteGroupOrItem",
            "IniDeleteEntry",
            "IniDeleteSection",
            "RegDeleteEntireKey",
            "RegClearValue",
            "RegDeleteKeyIfEmpty",
            "RegDeleteValue",
            "DecrementSharedCount",
        ]);
        all::<RefCarrier>(&["ValueName", "Data", "Segment", "Binary"]);
        all::<AnchorKind>(&["Root", "Exe", "ProgId", "Clsid", "Aumid", "Token"]);
    }

    #[test]
    fn json_schema_is_generated() {
        let text = serde_json::to_string(&schemars::schema_for!(Fingerprint)).unwrap();
        assert!(text.contains(r#""const":"purge.fp/0""#), "{text}");
        for name in [
            "mega_vendor",
            "outside_root_files",
            "package_families",
            "RegDeleteKeyIfEmpty",
            "existed_before",
            "parent_subkeys",
            "fully_attributed",
            "openwith_ours",
            "vendor_backup",
            "CoRemovedProduct",
            "ubr",
            "t_start",
            "msi_unknown_all_ctx",
            "warnings",
        ] {
            assert!(text.contains(name), "schema lacks {name}");
        }
    }
}
