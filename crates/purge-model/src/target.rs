//! What an item of a plan acts on.

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

/// Reads a value name, where JSON `null` means the default value (as `""`). A missing field is still an
/// error. rigtool writes `""`, but older rig output and hand-written plans may use `null`.
fn value_name<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
}

/// A thing on the system that a candidate or plan item refers to.
///
/// Serialised as an object tagged by `"type"`, exactly as in vm/RIG.md §5 and §7, e.g.
/// `{"type":"RegValue","path":"HKLM\\SOFTWARE\\X","name":"Y"}`. A value `name` of `null` reads as `""`
/// (the default value); it is always written as a string.
///
/// This is the one vocabulary for both plans (§7) and the rig's `truth.json` items (§5).
/// [`Target::RegValueChanged`] is truth-only: a plan never offers it, because removing a changed value is
/// never right; the fix is a [`Target::RegMultiSzSegment`] edit.
///
/// Registry paths use canonical roots (`HKLM\SOFTWARE\…`, `HKU\<SID>\…`, `HKU\<SID>_Classes\…`); file
/// paths are absolute. Canonicalisation itself lives in `purge-guard`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type")]
pub enum Target {
    /// A file or directory.
    Path {
        /// Absolute path, without a `\\?\` prefix.
        path: String,
    },
    /// A registry key and everything under it.
    RegKey {
        /// Canonical key path.
        path: String,
    },
    /// One named value of a registry key.
    RegValue {
        /// Canonical key path.
        path: String,
        /// Value name; empty for the key's default value.
        #[serde(deserialize_with = "value_name")]
        #[schemars(with = "Option<String>")]
        name: String,
    },
    /// A value that existed before the install and was changed by it (rig truth only, vm/RIG.md §5; e.g. a
    /// segment appended to `PATH`). Plans never contain it.
    RegValueChanged {
        /// Canonical key path.
        path: String,
        /// Value name; empty for the key's default value.
        #[serde(deserialize_with = "value_name")]
        #[schemars(with = "Option<String>")]
        name: String,
        /// Data before the install (preview, or hash when there is no preview).
        #[serde(default)]
        before: String,
        /// Data after the install (preview, or hash when there is no preview).
        #[serde(default)]
        after: String,
    },
    /// One segment of a list-like value (a `;`-separated `REG_SZ`/`REG_EXPAND_SZ` such as `PATH`, or one
    /// string of a `REG_MULTI_SZ`). Acting on it edits the value instead of deleting it.
    RegMultiSzSegment {
        /// Canonical key path.
        path: String,
        /// Value name; empty for the key's default value.
        #[serde(deserialize_with = "value_name")]
        #[schemars(with = "Option<String>")]
        name: String,
        /// The segment text.
        segment: String,
    },
    /// A Windows service.
    Service {
        /// Service (key) name, not the display name.
        name: String,
    },
    /// A Task Scheduler task.
    Task {
        /// Full task path, e.g. `\Vendor\Updater`.
        path: String,
    },
    /// A Windows Firewall rule.
    FirewallRule {
        /// Rule instance id. Rules are matched by id only, because display names are not unique.
        id: String,
    },
    /// An installed AppX/MSIX package.
    AppxPackage {
        /// Package full name.
        full_name: String,
    },
}
