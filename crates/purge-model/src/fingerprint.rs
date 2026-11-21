//! The fingerprint document, `purge.fp/0`: everything the engine learned about one app **before** its
//! uninstaller ran (ENGINE_PLAN.md §5.2 "Fingerprint", §3.4 `purge-engine harvest … -o fp.json`).
//!
//! The harvest writes it; the uninstall step adds the time window, the verify-gone result and the
//! co-removed products; the scan reads it and needs no other knowledge of the app. It is self-contained on
//! purpose: after the uninstall the registry and the install directory can no longer be asked.
//!
//! The M1a fingerprint holds what the M1a harvesters produce. MSI rows, Burn children, services, tasks and
//! firewall rules join it with M1b (`msi`, `burn`, `sys`, see `fingerprint_m1b`); fields added later
//! default to empty when absent and are not written when empty, so the schema id stays `purge.fp/0`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::fingerprint_m1b::{BurnFacts, MsiFacts, SysObjects};
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

/// How far a baseline view can be trusted when it says "this key is not Windows' own"
/// (BASELINE_LOCAL_DESIGN.md §4.1). Serialised by its variant name.
///
/// Presence ("Windows has it") blocks at every level. Absence is *proof* only at [`BaselineTrust::Exact`];
/// at `Merged` and `Local` it is *inferred* and under the trust cap (invariant L4: it never makes an item
/// Safe or preselected); at `None` it is never answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum BaselineTrust {
    /// A shipped baseline matches the host's (edition, build, ubr): absence is proof, as at the M1b gate.
    Exact,
    /// No exact match; a complete local baseline merged with at least one shipped neighbour.
    Merged,
    /// No exact match and no neighbour; a complete local baseline alone.
    Local,
    /// Anything else: absence is never answered, the scan works values-only.
    None,
}

impl BaselineTrust {
    /// Whether absence at this trust is *inferred*, so that the trust cap applies: `Merged` and `Local`.
    /// `Exact` proves and `None` never answers, so neither is capped.
    #[must_use]
    pub fn is_inferred(self) -> bool {
        match self {
            BaselineTrust::Merged | BaselineTrust::Local => true,
            BaselineTrust::Exact | BaselineTrust::None => false,
        }
    }

    /// Strength rank: Exact > Merged > Local > None.
    fn rank(self) -> u8 {
        match self {
            BaselineTrust::Exact => 3,
            BaselineTrust::Merged => 2,
            BaselineTrust::Local => 1,
            BaselineTrust::None => 0,
        }
    }

    /// The weaker of the two: what an absence fact stored at harvest counts as at scan time,
    /// `min(harvest trust, scan trust)` (design §4.5). Never stronger than either argument.
    #[must_use]
    pub fn min(self, other: BaselineTrust) -> BaselineTrust {
        if other.rank() < self.rank() {
            other
        } else {
            self
        }
    }

    /// The trust to hand to the policy (`PolicyCtx::baseline_trust`) for a scan made with a view of trust
    /// `scan` from a fingerprint harvested at trust `harvest`: inferred as soon as **either** is, because
    /// the candidates of one scan mix absences answered now with absence facts stored at harvest. (The
    /// plain minimum would be wrong here: `min(Merged, None)` is `None`, which is not capped.) When both
    /// are inferred it is the weaker of the two; when neither is, it is `scan`.
    #[must_use]
    pub fn for_policy(scan: BaselineTrust, harvest: BaselineTrust) -> BaselineTrust {
        match (scan.is_inferred(), harvest.is_inferred()) {
            (true, true) => scan.min(harvest),
            (false, true) => harvest,
            (true, false) | (false, false) => scan,
        }
    }

    /// The trust of the absence answers a **presence-only** engine takes from a view of this trust
    /// (DECISIONS.md, Post-M1b, 2026-11-21 "The local baseline ships presence-only"): `Exact` stays
    /// `Exact`; `Merged`, `Local` and `None` are `None`, because below Exact no absence is consumed at
    /// all and the view only says "this is Windows' own". It is what a harvest records beside its
    /// absence facts and what a scan hands on as its own trust while the A side is not wired.
    #[must_use]
    pub fn presence_only(self) -> BaselineTrust {
        match self {
            BaselineTrust::Exact => BaselineTrust::Exact,
            BaselineTrust::Merged | BaselineTrust::Local | BaselineTrust::None => {
                BaselineTrust::None
            }
        }
    }

    /// The value of the evidence detail fact `baseline_trust` for this trust: `exact`, `merged`, `local`
    /// or `none` (design §4.4 layer 1).
    #[must_use]
    pub fn as_fact(self) -> &'static str {
        match self {
            BaselineTrust::Exact => "exact",
            BaselineTrust::Merged => "merged",
            BaselineTrust::Local => "local",
            BaselineTrust::None => "none",
        }
    }
}

impl std::fmt::Display for BaselineTrust {
    /// [`BaselineTrust::as_fact`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_fact())
    }
}

/// The baseline view a fingerprint was harvested with (design §4.5): the trust beside the absence facts
/// the fingerprint stores (`ext_journal`, the subtree records).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct BaselineViewRef {
    /// The view's name: `Professional-26340.9882` for an exact baseline, `local-…+2` for a merged one.
    pub name: String,
    /// Its trust at harvest.
    pub trust: BaselineTrust,
    /// The source id of the local baseline the view held; `None` for an exact view or one without a
    /// local baseline.
    #[serde(default)]
    pub local_id: Option<String>,
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
    /// The app's own uninstaller files, as canonical paths: the program its `UninstallString` and
    /// `QuietUninstallString` run and, for Inno Setup, the uninstall log and message file of the same
    /// number. Empty when the app has no uninstaller program of its own (MSI) or the fingerprint is
    /// older than this field; a file named like an uninstaller is then nobody's in particular.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uninstallers: Vec<String>,
    /// Registry keys the harvest looked at that existed before the app was installed, by the
    /// registry's own clock against the exact start of the install (canonical paths; empty when
    /// that start is not known). Such a key is not a skeleton of the app, whatever it holds: an
    /// empty key somebody made before the install looks like the app's once the app wrote its one
    /// value into it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub older_keys: Vec<String>,
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
    /// The app's MSI products (M1b). Absent, and left out when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub msi: Vec<MsiFacts>,
    /// The app's Burn bundle (M1b). Absent, and left out when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burn: Option<BurnFacts>,
    /// The services, tasks and firewall rules the harvest recorded as the app's (M1b). Absent, and left
    /// out when empty.
    #[serde(default, skip_serializing_if = "SysObjects::is_empty")]
    pub sys: SysObjects,
    /// The baseline view the harvest ran with (BASELINE_LOCAL_DESIGN.md §4.5). Absent from fingerprints
    /// written before the field existed, and left out when `None`, so those read and write unchanged;
    /// what such a fingerprint counts as is [`Fingerprint::harvest_trust`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_view: Option<BaselineViewRef>,
}

impl Fingerprint {
    /// The trust of the baseline the harvest's absence facts were made with (design §4.5).
    ///
    /// `exact_shipped`: whether the caller holds a shipped baseline that matches [`Fingerprint::os`]
    /// exactly (name and header), i.e. what the M1b engine required before it used a baseline at all.
    ///
    /// - No `baseline_view` (an old fingerprint): `Exact` when `exact_shipped`, otherwise `None`, which
    ///   is what such a fingerprint was.
    /// - A recorded `Exact` is believed only when `exact_shipped` and the recorded name is the
    ///   fingerprint's own [`OsInfo::baseline_name`]; otherwise it is `None`. A document can therefore
    ///   never claim proof the engine cannot check against a shipped file.
    /// - A recorded `Merged`, `Local` or `None` is returned as recorded: the first two are under the
    ///   trust cap, the last answers no absence.
    pub fn harvest_trust(&self, exact_shipped: bool) -> BaselineTrust {
        match &self.baseline_view {
            None if exact_shipped => BaselineTrust::Exact,
            None => BaselineTrust::None,
            Some(view) => match view.trust {
                BaselineTrust::Exact if exact_shipped && view.name == self.os.baseline_name() => {
                    BaselineTrust::Exact
                }
                BaselineTrust::Exact => BaselineTrust::None,
                recorded => recorded,
            },
        }
    }

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
            "uninstallers": ["C:\\Program Files\\Microsoft VS Code\\unins000.exe"],
            "older_keys": ["HKLM\\SOFTWARE\\Classes\\.gemspec"],
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

    /// A fingerprint the M1a gate harvest wrote (7-Zip, `m1a-rerun` run `r4-7zip`) reads, has the M1b
    /// fields at their defaults, and writes back byte for byte: the M1b fields add nothing to it.
    #[test]
    fn fingerprint_m1a_document_round_trips_byte_equal() {
        let text = include_str!("../testdata/m1a-7zip.fp.json").replace("\r\n", "\n");
        let fp: Fingerprint = serde_json::from_str(&text).unwrap();
        assert!(fp.msi.is_empty() && fp.burn.is_none() && fp.sys.is_empty());
        assert_eq!(fp.sys, SysObjects::default());
        let written = serde_json::to_string_pretty(&fp).unwrap();
        assert_eq!(written, text.trim_end());
        for name in ["\"msi\"", "\"burn\"", "\"sys\""] {
            assert!(!written.contains(name), "{name}");
        }
        // The in-memory samples too, compact and pretty.
        let v = sample();
        let fp: Fingerprint = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(serde_json::to_value(&fp).unwrap(), v);
    }

    /// Every M1b field populated: reads, writes back unchanged, and a sparse document still defaults.
    #[test]
    fn fingerprint_m1b_fields_round_trip() {
        let mut v = minimal("HKLM|64|{11111111-2222-3333-4444-555555555555}");
        v["msi"] = json!([{
            "product_code": "{11111111-2222-3333-4444-555555555555}",
            "packed_code": "11111111222233334444555555555555",
            "upgrade_code": null, "context": "Machine", "user_sid": null,
            "local_package": "C:\\Windows\\Installer\\1a2b3c.msi", "package_readable": true,
            "components": [
                {"component_id": "{AAAAAAAA-0000-0000-0000-000000000001}",
                 "key_path": {"kind": "file", "path": "C:\\Program Files\\Vendor\\app.exe"},
                 "other_clients": [], "shared_dll": false},
                {"component_id": "{AAAAAAAA-0000-0000-0000-000000000002}",
                 "key_path": {"kind": "registry", "key": "HKU\\*\\Software\\Vendor", "name": null},
                 "other_clients": ["00000000000000000000000000000000"], "shared_dll": true},
                {"component_id": "{AAAAAAAA-0000-0000-0000-000000000003}",
                 "key_path": {"kind": "none"}, "other_clients": [], "shared_dll": false}
            ],
            "registry_rows": [{"key": "HKLM\\SOFTWARE\\Vendor", "name": null, "whole_key": true,
                               "component": "Main", "row": "reg1"}],
            "services": [{"name": "VendorSvc", "component": "Svc"}],
            "source_dirs": ["C:\\Program Files\\Vendor"],
            "custom_actions": 3, "unresolved_rows": 1
        }]);
        v["burn"] = json!({
            "bundle_id": "{BBBBBBBB-0000-0000-0000-000000000001}",
            "provider_key": "Vendor.Bundle", "cache_path": null,
            "packages": [{"provider_key": "Vendor.Pkg", "product_code": null, "cache_dir": null,
                          "other_dependents": ["Other.Bundle"]}],
            "dependents_at_harvest": []
        });
        v["sys"] = json!({
            "services": [{"identity": {"name": "VendorSvc", "image_path": "\"C:\\x\\svc.exe\"",
                                       "service_dll": null, "service_type": 16, "start": 2,
                                       "object_name": "LocalSystem"},
                          "program": "C:\\x\\svc.exe", "why": "msi_service_row"}],
            "tasks": [{"identity": {"path": "\\Vendor\\Update",
                                    "actions": [{"kind": "exec", "path": "C:\\x\\up.exe",
                                                 "arguments": null, "working_dir": null}]},
                       "program": "C:\\x\\up.exe", "why": "program_in_root"}],
            "firewall_rules": [{"identity": {"id": "{CCCCCCCC-0000-0000-0000-000000000001}",
                                             "rule": "v2.33|Action=Allow|App=C:\\x\\a.exe|Name=X|"},
                                "program": null, "why": "program_is_app_exe"}]
        });
        let fp: Fingerprint = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(fp.msi[0].components.len(), 3);
        assert_eq!(
            fp.msi[0].components[2].key_path,
            crate::fingerprint_m1b::MsiKeyPath::None
        );
        assert_eq!(fp.sys.services[0].identity.service_type, 16);
        assert_eq!(serde_json::to_value(&fp).unwrap(), v);
        let text = serde_json::to_string_pretty(&fp).unwrap();
        assert_eq!(serde_json::from_str::<Fingerprint>(&text).unwrap(), fp);

        // One list of `sys` alone reads; the others default.
        let mut sparse = minimal("HKLM|64|Other");
        sparse["sys"] = json!({"tasks": []});
        let fp: Fingerprint = serde_json::from_value(sparse).unwrap();
        assert!(fp.sys.is_empty());
        assert!(!serde_json::to_string(&fp).unwrap().contains("\"sys\""));
        // An unknown key path or reason does not read.
        let mut bad = v.clone();
        bad["msi"][0]["components"][0]["key_path"]["kind"] = json!("folder");
        assert!(serde_json::from_value::<Fingerprint>(bad).is_err());
        let mut bad = v;
        bad["sys"]["tasks"][0]["why"] = json!("NameMatch");
        assert!(serde_json::from_value::<Fingerprint>(bad).is_err());

        let schema = serde_json::to_string(&schemars::schema_for!(Fingerprint)).unwrap();
        for name in [
            "packed_code",
            "other_clients",
            "whole_key",
            "dependents_at_harvest",
            "firewall_rules",
            "msi_service_row",
            "other_kind",
        ] {
            assert!(schema.contains(name), "schema lacks {name}");
        }
    }

    /// BL-POLICY: the `baseline_view` field. A fingerprint without it (every fingerprint written so far)
    /// reads, has `None`, writes back without the field, and counts as Exact or None by the shipped
    /// baseline alone; with it, every trust round-trips.
    #[test]
    fn fingerprint_baseline_view_round_trips_and_old_documents_default() {
        // Old documents: the full sample, the minimal one, and the M1a gate harvest, byte for byte.
        for old in [sample(), minimal("HKLM|64|Other")] {
            assert!(old.get("baseline_view").is_none());
            let fp: Fingerprint = serde_json::from_value(old.clone()).unwrap();
            assert_eq!(fp.baseline_view, None);
            assert_eq!(serde_json::to_value(&fp).unwrap(), old);
            assert!(
                !serde_json::to_string(&fp)
                    .unwrap()
                    .contains("baseline_view")
            );
            assert_eq!(fp.harvest_trust(true), BaselineTrust::Exact);
            assert_eq!(fp.harvest_trust(false), BaselineTrust::None);
        }
        let text = include_str!("../testdata/m1a-7zip.fp.json").replace("\r\n", "\n");
        let fp: Fingerprint = serde_json::from_str(&text).unwrap();
        assert_eq!(fp.baseline_view, None);
        assert_eq!(serde_json::to_string_pretty(&fp).unwrap(), text.trim_end());

        // With the field: every trust, with and without a local id.
        for (trust, wire) in [
            (BaselineTrust::Exact, "Exact"),
            (BaselineTrust::Merged, "Merged"),
            (BaselineTrust::Local, "Local"),
            (BaselineTrust::None, "None"),
        ] {
            for local_id in [json!(null), json!("9f86d081884c7d65")] {
                let mut v = minimal("HKLM|64|Other");
                v["baseline_view"] = json!({
                    "name": "local-Professional-26340.9882-9f86d081+2",
                    "trust": wire,
                    "local_id": local_id
                });
                let fp: Fingerprint = serde_json::from_value(v.clone()).unwrap();
                let view = fp.baseline_view.as_ref().unwrap();
                assert_eq!(view.trust, trust);
                assert_eq!(view.local_id.is_some(), !local_id.is_null());
                assert_eq!(serde_json::to_value(&fp).unwrap(), v);
                let text = serde_json::to_string_pretty(&fp).unwrap();
                assert_eq!(serde_json::from_str::<Fingerprint>(&text).unwrap(), fp);
            }
        }
        // `local_id` may be absent; the name and the trust may not, and an unknown trust does not read.
        let with = |view: Value| {
            let mut v = minimal("HKLM|64|Other");
            v["baseline_view"] = view;
            serde_json::from_value::<Fingerprint>(v)
        };
        let short = with(json!({"name": "Professional-26340.9882", "trust": "Exact"})).unwrap();
        assert_eq!(short.baseline_view.as_ref().unwrap().local_id, None);
        assert!(with(json!({"name": "x"})).is_err());
        assert!(with(json!({"trust": "Merged"})).is_err());
        assert!(with(json!({"name": "x", "trust": "Proven"})).is_err());
        assert!(with(json!({"name": "x", "trust": "exact"})).is_err());
        // An explicit null reads as "no field" and is not written back.
        let null = with(json!(null)).unwrap();
        assert_eq!(null.baseline_view, None);

        // In a co-removed product's fingerprint too.
        let mut v = sample();
        v["co_removed"][1]["fingerprint"]["baseline_view"] =
            json!({"name": "local-x", "trust": "Local", "local_id": "ab"});
        let fp: Fingerprint = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(serde_json::to_value(&fp).unwrap(), v);

        let schema = serde_json::to_string(&schemars::schema_for!(Fingerprint)).unwrap();
        for name in [
            "baseline_view",
            "BaselineViewRef",
            "BaselineTrust",
            "local_id",
            "Merged",
        ] {
            assert!(schema.contains(name), "schema lacks {name}");
        }
        // The field is optional in the schema: an old document validates.
        let schema: Value = serde_json::to_value(schemars::schema_for!(Fingerprint)).unwrap();
        let required = schema["required"].as_array().unwrap();
        assert!(!required.contains(&json!("baseline_view")), "{required:?}");
    }

    /// What a fingerprint's absence facts count as (design §4.5): a recorded Exact is believed only with
    /// the matching shipped baseline in hand, and only under the fingerprint's own baseline name.
    #[test]
    fn harvest_trust_never_exceeds_what_the_shipped_baseline_confirms() {
        let fp_with = |name: &str, trust: BaselineTrust| {
            let mut fp: Fingerprint = serde_json::from_value(minimal("HKLM|64|Other")).unwrap();
            fp.baseline_view = Some(BaselineViewRef {
                name: name.into(),
                trust,
                local_id: None,
            });
            fp
        };
        let own = "Professional-26340.9882";
        let exact = fp_with(own, BaselineTrust::Exact);
        assert_eq!(exact.harvest_trust(true), BaselineTrust::Exact);
        assert_eq!(exact.harvest_trust(false), BaselineTrust::None);
        // Exact under another name (a neighbour, a local file) is not Exact.
        for name in [
            "EnterpriseSEval-26100.1742",
            "local-Professional-26340.9882-ab",
            "",
        ] {
            let fp = fp_with(name, BaselineTrust::Exact);
            assert_eq!(fp.harvest_trust(true), BaselineTrust::None, "{name}");
            assert_eq!(fp.harvest_trust(false), BaselineTrust::None, "{name}");
        }
        // Below Exact the record stands, whatever is shipped now: it is never raised.
        for trust in [
            BaselineTrust::Merged,
            BaselineTrust::Local,
            BaselineTrust::None,
        ] {
            for shipped in [true, false] {
                assert_eq!(fp_with(own, trust).harvest_trust(shipped), trust);
            }
        }
    }

    #[test]
    fn baseline_trust_order_and_policy_trust() {
        use BaselineTrust::{Exact, Local, Merged, None};
        let all = [Exact, Merged, Local, None];
        for t in all {
            assert_eq!(t.is_inferred(), matches!(t, Merged | Local), "{t:?}");
        }
        assert_eq!(
            all.map(BaselineTrust::as_fact),
            ["exact", "merged", "local", "none"]
        );
        // `min` is the weaker one, in the order Exact > Merged > Local > None.
        for (i, a) in all.into_iter().enumerate() {
            for (j, b) in all.into_iter().enumerate() {
                let weaker = all[i.max(j)];
                assert_eq!(a.min(b), weaker, "{a:?} {b:?}");
                assert_eq!(b.min(a), weaker, "{a:?} {b:?}");
                // The policy trust is inferred exactly when either side is, and then never the
                // stronger of two inferred ones.
                let p = BaselineTrust::for_policy(a, b);
                assert_eq!(
                    p.is_inferred(),
                    a.is_inferred() || b.is_inferred(),
                    "{a:?} {b:?}"
                );
                if a.is_inferred() && b.is_inferred() {
                    assert_eq!(p, weaker);
                }
                if !p.is_inferred() {
                    assert_eq!(p, a, "the scan's own trust when nothing is inferred");
                }
            }
        }
        assert_eq!(BaselineTrust::for_policy(Merged, None), Merged);
        assert_eq!(BaselineTrust::for_policy(Exact, Merged), Merged);
        assert_eq!(BaselineTrust::for_policy(None, Local), Local);
        assert_eq!(BaselineTrust::for_policy(Exact, None), Exact);
        // Presence-only: below Exact no absence is consumed.
        assert_eq!(
            all.map(BaselineTrust::presence_only),
            [Exact, None, None, None]
        );
        assert_eq!(Merged.to_string(), "merged");
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
            "uninstallers",
            "older_keys",
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
