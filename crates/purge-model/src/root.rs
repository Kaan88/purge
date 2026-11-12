//! Roots: the directories an app is installed in or refers to (ENGINE_PLAN.md §5.2).
//!
//! A root is only a claim until `validate_root` (in `purge-guard`) accepts it; the fingerprint holds
//! validated roots only. What a root may prove depends on its [`RootKind`], and what scope of target that
//! proof may reach depends on its [`SourceTrust`] (Rule T, §5.3).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What a root is, which bounds the evidence it can give.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum RootKind {
    /// Where the app is installed, named by the installer's own record (ARP `InstallLocation`, MSI
    /// component paths, the Inno `{app}`, AppX `InstalledLocation`). Files under it are Tier A.
    InstallRoot,
    /// A directory the app refers to as a data, library, output, download or save location. At most
    /// `ReferencedByApp` (Tier B), always user data, never a whole-directory target.
    ReferencedDataDir,
    /// A root guessed from `DisplayIcon` or the uninstaller's directory. Tier B only, never quarantined
    /// whole.
    InferredRoot,
}

/// Which record a root was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum RootSource {
    /// The ARP entry's `InstallLocation` value.
    ArpInstallLocation,
    /// The Inno Setup `{app}` directory (`Inno Setup: App Path`, or the uninstall log's location).
    InnoApp,
    /// An MSI component path.
    MsiComponent,
    /// An AppX package's `InstalledLocation`.
    AppxInstalledLocation,
    /// The directory of the ARP entry's `DisplayIcon`.
    DisplayIcon,
    /// The directory of the uninstaller named by `UninstallString`.
    UninstallerDir,
    /// A path referenced by the app's own configuration.
    Referenced,
}

impl RootSource {
    /// The strongest kind of root this source may establish (§5.2 "Root kinds").
    pub fn root_kind(self) -> RootKind {
        match self {
            RootSource::ArpInstallLocation
            | RootSource::InnoApp
            | RootSource::MsiComponent
            | RootSource::AppxInstalledLocation => RootKind::InstallRoot,
            RootSource::DisplayIcon | RootSource::UninstallerDir => RootKind::InferredRoot,
            RootSource::Referenced => RootKind::ReferencedDataDir,
        }
    }
}

/// Who could have written the record a fact was read from (Rule T, §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum SourceTrust {
    /// Only administrators can write the source (HKLM, Program Files, the admin store).
    AdminOnly,
    /// The user can write the source (an `HKU` ARP entry, `%LOCALAPPDATA%` stores). Such evidence never
    /// attributes machine-scope targets at Tier A.
    UserWritable,
}

/// A validated root of an app.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Root {
    /// Canonical absolute path of the directory, without a trailing `\`.
    pub path: String,
    /// What the root is.
    pub kind: RootKind,
    /// The record it was read from.
    pub source: RootSource,
    /// Who could have written that record.
    pub trust: SourceTrust,
    /// Serial number of the volume the path was on at harvest, when it could be read. `DanglingRef`
    /// evidence needs the same volume mounted again (§5.3).
    pub volume_serial: Option<u32>,
    /// Whether the root's parent directory existed at harvest. A missing path counts as dangling only when
    /// its nearest existing ancestor is that recorded parent.
    pub parent_existed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn root_round_trips() {
        let v = json!({
            "path": "C:\\Program Files\\Git", "kind": "InstallRoot", "source": "InnoApp",
            "trust": "AdminOnly", "volume_serial": 305419896u32, "parent_existed": true
        });
        let root: Root = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(root.kind, RootKind::InstallRoot);
        assert_eq!(root.volume_serial, Some(0x1234_5678));
        assert_eq!(serde_json::to_value(&root).unwrap(), v);
        assert!(schemars::schema_for!(Root).as_object().is_some());
    }

    #[test]
    fn every_enum_value_round_trips() {
        for (kind, source) in [
            ("InstallRoot", "ArpInstallLocation"),
            ("InstallRoot", "InnoApp"),
            ("InstallRoot", "MsiComponent"),
            ("InstallRoot", "AppxInstalledLocation"),
            ("InferredRoot", "DisplayIcon"),
            ("InferredRoot", "UninstallerDir"),
            ("ReferencedDataDir", "Referenced"),
        ] {
            let k: RootKind = serde_json::from_value(json!(kind)).unwrap();
            let s: RootSource = serde_json::from_value(json!(source)).unwrap();
            assert_eq!(serde_json::to_value(k).unwrap(), json!(kind));
            assert_eq!(serde_json::to_value(s).unwrap(), json!(source));
            // Only installer records give an InstallRoot.
            assert_eq!(s.root_kind(), k, "{source}");
        }
        for trust in ["AdminOnly", "UserWritable"] {
            let t: SourceTrust = serde_json::from_value(json!(trust)).unwrap();
            assert_eq!(serde_json::to_value(t).unwrap(), json!(trust));
        }
    }
}
