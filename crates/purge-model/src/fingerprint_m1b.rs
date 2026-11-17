//! M1b additions to the fingerprint document (contract C-FP): what the harvest records about the app's
//! MSI products, its Burn bundle, and the services, scheduled tasks and firewall rules it owns.
//!
//! [`Fingerprint`](crate::Fingerprint) holds them in three fields that default when absent and are left
//! out when empty, so every `purge.fp/0` document written before M1b reads and writes back byte for byte.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::MsiContext;
use crate::object::{FirewallIdentity, ServiceIdentity, TaskIdentity};

/// What the harvest read about one MSI product of the app: its registration and its cached package.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct MsiFacts {
    /// ProductCode, `{GUID}` in upper case.
    pub product_code: String,
    /// The packed (registry) form of the ProductCode: 32 upper-case hex digits.
    pub packed_code: String,
    /// UpgradeCode, `{GUID}` in upper case, when the package has one.
    pub upgrade_code: Option<String>,
    /// The context the product is installed in.
    pub context: MsiContext,
    /// SID of the user a per-user product belongs to; `None` for a per-machine product.
    pub user_sid: Option<String>,
    /// Path of the cached package (`LocalPackage`), when registered.
    pub local_package: Option<String>,
    /// Whether the cached package could be opened and its tables read. When false, the lists below
    /// hold only what the registration tells.
    pub package_readable: bool,
    /// The product's components.
    pub components: Vec<MsiComponentFact>,
    /// The rows of the package's `Registry` table, resolved.
    pub registry_rows: Vec<MsiRegRow>,
    /// The rows of the package's `ServiceInstall` table.
    pub services: Vec<MsiServiceRow>,
    /// The resolved directories of the package's `Directory` table that hold its files.
    pub source_dirs: Vec<String>,
    /// Number of rows of the `CustomAction` table (what the uninstall may have done besides the tables).
    pub custom_actions: u32,
    /// Number of rows that could not be resolved (a property without a value, a formatted string).
    pub unresolved_rows: u32,
}

/// One component of an MSI product, with the clients Windows Installer records for it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct MsiComponentFact {
    /// ComponentId, `{GUID}` in upper case.
    pub component_id: String,
    /// The component's key path.
    pub key_path: MsiKeyPath,
    /// Packed product codes of the other products that are clients of the component.
    /// `00000000000000000000000000000000` means the component is permanent.
    pub other_clients: Vec<String>,
    /// The key path is a file counted in `SharedDLLs`.
    pub shared_dll: bool,
}

/// The key path of an MSI component. Serialised as an object tagged by `"kind"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind")]
pub enum MsiKeyPath {
    /// A file.
    #[serde(rename = "file")]
    File {
        /// Canonical absolute path.
        path: String,
    },
    /// A registry key or value.
    #[serde(rename = "registry")]
    Registry {
        /// Full canonical key path (`HKLM\...` or `HKU\<sid>\...`).
        key: String,
        /// Value name; `None` for the key itself.
        name: Option<String>,
    },
    /// No key path (a component without one, or a directory).
    #[serde(rename = "none")]
    None,
}

/// One row of an MSI package's `Registry` table, resolved to a canonical key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct MsiRegRow {
    /// Canonical key path. A per-user row of a per-machine install has the literal user segment
    /// `HKU\*`.
    pub key: String,
    /// Value name; `None` for the default value.
    pub name: Option<String>,
    /// `Registry.Name` is `-` or `*` with a null `Value`: the key and everything under it is removed on
    /// uninstall.
    pub whole_key: bool,
    /// The component the row belongs to.
    pub component: String,
    /// The row's primary key in the `Registry` table.
    pub row: String,
}

/// One row of an MSI package's `ServiceInstall` table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct MsiServiceRow {
    /// Service name.
    pub name: String,
    /// The component the row belongs to.
    pub component: String,
}

/// What the harvest read about the app's Burn bundle.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct BurnFacts {
    /// The bundle id (`{GUID}`).
    pub bundle_id: String,
    /// The bundle's dependency provider key, when registered.
    pub provider_key: Option<String>,
    /// The bundle's folder in the Package Cache, when present.
    pub cache_path: Option<String>,
    /// The bundle's packages.
    pub packages: Vec<BurnPackage>,
    /// Provider keys of the bundles that depended on this bundle at harvest.
    pub dependents_at_harvest: Vec<String>,
}

/// One package of a Burn bundle.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct BurnPackage {
    /// The package's dependency provider key.
    pub provider_key: String,
    /// ProductCode of an MSI package, `{GUID}` in upper case.
    pub product_code: Option<String>,
    /// The package's folder in the Package Cache, when present.
    pub cache_dir: Option<String>,
    /// Dependents of the package other than this bundle, at harvest.
    pub other_dependents: Vec<String>,
}

/// Why the harvest recorded a system object as the app's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObjectWhy {
    /// The object's program lies under one of the app's roots.
    ProgramInRoot,
    /// The object's program is one of the app's exes.
    ProgramIsAppExe,
    /// A `ServiceInstall` row of one of the app's MSI products names the service.
    MsiServiceRow,
    /// A scheduled task whose every action is a COM handler of one of the app's own classes
    /// (`Anchors::clsids`: a class whose server was the app's file, or a `Class` row of the app's own
    /// MSI), with no exec action (R4 B2).
    AppComClass,
}

/// A service the harvest recorded as the app's.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct SysService {
    /// Its identity at harvest; its digest is what the scan compares with.
    pub identity: ServiceIdentity,
    /// The program file the service runs, resolved; `None` when it could not be resolved to one file.
    pub program: Option<String>,
    /// Why it is the app's.
    pub why: ObjectWhy,
}

/// A scheduled task the harvest recorded as the app's.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct SysTask {
    /// Its identity at harvest.
    pub identity: TaskIdentity,
    /// The program file its first exec action runs, resolved; `None` when it could not be resolved.
    pub program: Option<String>,
    /// Why it is the app's.
    pub why: ObjectWhy,
}

/// A firewall rule the harvest recorded as the app's.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct SysFirewallRule {
    /// Its identity at harvest.
    pub identity: FirewallIdentity,
    /// The program file the rule applies to (`App=`), resolved; `None` when it has none or it could
    /// not be resolved.
    pub program: Option<String>,
    /// Why it is the app's.
    pub why: ObjectWhy,
}

/// The system objects the harvest recorded as the app's.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct SysObjects {
    /// Services.
    #[serde(default)]
    pub services: Vec<SysService>,
    /// Scheduled tasks.
    #[serde(default)]
    pub tasks: Vec<SysTask>,
    /// Firewall rules.
    #[serde(default)]
    pub firewall_rules: Vec<SysFirewallRule>,
}

impl SysObjects {
    /// Whether no object is recorded. A fingerprint leaves the field out then.
    pub fn is_empty(&self) -> bool {
        self.services.is_empty() && self.tasks.is_empty() && self.firewall_rules.is_empty()
    }
}
