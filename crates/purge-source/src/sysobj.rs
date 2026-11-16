//! What the two M1b [`SystemSource`] methods return (contract C-SOURCE): the MSI tables of one cached
//! installer package ([`SystemSource::msi_tables`]) and the scheduled tasks ([`SystemSource::tasks`]), with
//! the limits every implementation enforces.
//!
//! Services and firewall rules have no source method: they are read from the registry through
//! [`RegistrySource`](crate::registry::RegistrySource) (C-SYSOBJ), as are the MSI component clients.
//!
//! # Limits
//!
//! - At most [`MAX_TABLE_ROWS`] rows per table. A longer table is cut there and the result says
//!   [`MsiTables::truncated`]; the caller then treats the package as unreadable.
//! - At most [`MAX_CELL_BYTES`] bytes per string cell. A row with a longer cell is dropped and counted as
//!   truncation (the row cannot be read faithfully, and a row with a cell left out would mean something
//!   else).
//! - At most [`MAX_TASKS`] tasks. A longer list is an error ([`TOO_MANY_TASKS`]), never a cut list: a cut
//!   list would read as "these are all the tasks".
//!
//! [`SystemSource`]: crate::system::SystemSource
//! [`SystemSource::msi_tables`]: crate::system::SystemSource::msi_tables
//! [`SystemSource::tasks`]: crate::system::SystemSource::tasks

use purge_model::object::TaskIdentity;
use serde::{Deserialize, Serialize};

use crate::types::{SourceError, SourceResult};

/// The most rows one table of [`MsiTables`] holds.
pub const MAX_TABLE_ROWS: usize = 200_000;

/// The longest string cell, in UTF-8 bytes, that [`MsiTables`] keeps.
pub const MAX_CELL_BYTES: usize = 64 * 1024;

/// The most tasks [`SystemSource::tasks`](crate::system::SystemSource::tasks) returns.
pub const MAX_TASKS: usize = 20_000;

/// The Win32 code of the [`SourceError::Other`] returned for more than [`MAX_TASKS`] tasks
/// (`ERROR_MORE_DATA`).
pub const TOO_MANY_TASKS: u32 = 234;

/// The rows of one cached MSI package (`LocalPackage`) that ownership needs. Strings are as stored in the
/// package: registry keys are `Formatted` and unresolved.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MsiTables {
    /// `Property` table: (Property, Value).
    pub properties: Vec<(String, String)>,
    /// `Component` table.
    pub components: Vec<MsiComponentRow>,
    /// `Registry` table.
    pub registry: Vec<MsiRegistryRaw>,
    /// `RemoveRegistry` table.
    pub remove_registry: Vec<MsiRegistryRaw>,
    /// `Class` table.
    pub classes: Vec<MsiClassRow>,
    /// `ProgId` table: the ProgId column.
    pub progids: Vec<String>,
    /// `Extension` table.
    pub extensions: Vec<MsiExtensionRow>,
    /// `TypeLib` table: the LibID column.
    pub typelibs: Vec<String>,
    /// `AppId` table: the AppId column.
    pub appids: Vec<String>,
    /// `ServiceInstall` table.
    pub service_install: Vec<MsiServiceRaw>,
    /// Number of rows in `CustomAction`.
    pub custom_action_count: u32,
    /// A table was cut at [`MAX_TABLE_ROWS`] or a row was dropped for a cell over [`MAX_CELL_BYTES`]; the
    /// caller treats the package as unreadable.
    pub truncated: bool,
}

/// One row of the `Component` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsiComponentRow {
    /// `Component` (the table key).
    pub component: String,
    /// `ComponentId` (a GUID); `None` for an unregistered component.
    pub component_id: Option<String>,
    /// `Attributes`.
    pub attributes: i32,
    /// `KeyPath`.
    pub key_path: Option<String>,
}

/// One row of the `Registry` or `RemoveRegistry` table, unresolved.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsiRegistryRaw {
    /// `Registry` / `RemoveRegistry` (the table key).
    pub row: String,
    /// `Root`: -1 (per-user or per-machine with the install), 0 HKCR, 1 HKCU, 2 HKLM, 3 HKU.
    pub root: i32,
    /// `Key`, `Formatted` and unresolved.
    pub key: String,
    /// `Name`.
    pub name: Option<String>,
    /// `Value` (`Registry` only).
    pub value: Option<String>,
    /// `Component_`.
    pub component: String,
}

/// One row of the `Class` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsiClassRow {
    /// `CLSID`.
    pub clsid: String,
    /// `Context` (`LocalServer32`, `InprocServer32`, ...).
    pub context: String,
    /// `Component_`.
    pub component: String,
    /// `ProgId_Default`.
    pub progid: Option<String>,
    /// `AppId_`.
    pub appid: Option<String>,
}

/// One row of the `Extension` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsiExtensionRow {
    /// `Extension`, without the dot.
    pub extension: String,
    /// `Component_`.
    pub component: String,
    /// `ProgId_`.
    pub progid: Option<String>,
}

/// One row of the `ServiceInstall` table, unresolved.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsiServiceRaw {
    /// `Name`, `Formatted`.
    pub name: String,
    /// `Component_`.
    pub component: String,
    /// `ServiceType`.
    pub service_type: i32,
    /// `StartType`.
    pub start_type: i32,
}

/// One scheduled task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskInfo {
    /// Path and actions. A task the scanning user cannot read keeps an empty action list.
    pub identity: TaskIdentity,
    /// The task is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// The task is hidden.
    #[serde(default)]
    pub hidden: bool,
    /// `RegistrationInfo/Author`.
    #[serde(default)]
    pub author: Option<String>,
    /// The task runs with a stored password (logon type `Password`).
    #[serde(default)]
    pub stored_password: bool,
    /// The principal's user id.
    #[serde(default)]
    pub run_as: Option<String>,
}

impl Default for TaskInfo {
    /// A task with an empty path and no actions. (Written out because `TaskIdentity` has no `Default`.)
    fn default() -> Self {
        Self {
            identity: TaskIdentity {
                path: String::new(),
                actions: Vec::new(),
            },
            enabled: false,
            hidden: false,
            author: None,
            stored_password: false,
            run_as: None,
        }
    }
}

/// Whether a string cell is within [`MAX_CELL_BYTES`].
pub fn cell_fits(cell: &str) -> bool {
    cell.len() <= MAX_CELL_BYTES
}

fn opt_fits(cell: &Option<String>) -> bool {
    cell.as_deref().is_none_or(cell_fits)
}

impl MsiComponentRow {
    /// Every string cell is within [`MAX_CELL_BYTES`].
    pub fn fits(&self) -> bool {
        cell_fits(&self.component) && opt_fits(&self.component_id) && opt_fits(&self.key_path)
    }
}

impl MsiRegistryRaw {
    /// Every string cell is within [`MAX_CELL_BYTES`].
    pub fn fits(&self) -> bool {
        cell_fits(&self.row)
            && cell_fits(&self.key)
            && opt_fits(&self.name)
            && opt_fits(&self.value)
            && cell_fits(&self.component)
    }
}

impl MsiClassRow {
    /// Every string cell is within [`MAX_CELL_BYTES`].
    pub fn fits(&self) -> bool {
        cell_fits(&self.clsid)
            && cell_fits(&self.context)
            && cell_fits(&self.component)
            && opt_fits(&self.progid)
            && opt_fits(&self.appid)
    }
}

impl MsiExtensionRow {
    /// Every string cell is within [`MAX_CELL_BYTES`].
    pub fn fits(&self) -> bool {
        cell_fits(&self.extension) && cell_fits(&self.component) && opt_fits(&self.progid)
    }
}

impl MsiServiceRaw {
    /// Every string cell is within [`MAX_CELL_BYTES`].
    pub fn fits(&self) -> bool {
        cell_fits(&self.name) && cell_fits(&self.component)
    }
}

/// At most [`MAX_TABLE_ROWS`] of the rows that fit; sets `truncated` when a row is dropped or the table is
/// cut. Never copies more than the limit.
fn capped<T: Clone>(rows: &[T], fits: impl Fn(&T) -> bool, truncated: &mut bool) -> Vec<T> {
    let mut out = Vec::with_capacity(rows.len().min(MAX_TABLE_ROWS));
    for row in rows {
        if !fits(row) {
            *truncated = true;
            continue;
        }
        if out.len() == MAX_TABLE_ROWS {
            *truncated = true;
            break;
        }
        out.push(row.clone());
    }
    out
}

impl MsiTables {
    /// A copy within the limits: every table cut at [`MAX_TABLE_ROWS`], rows with a cell over
    /// [`MAX_CELL_BYTES`] dropped, and [`truncated`](Self::truncated) set when either happened (or was
    /// already set).
    pub fn limited(&self) -> MsiTables {
        let mut t = self.truncated;
        let pair_fits = |(k, v): &(String, String)| cell_fits(k) && cell_fits(v);
        let str_fits = |s: &String| cell_fits(s);
        MsiTables {
            properties: capped(&self.properties, pair_fits, &mut t),
            components: capped(&self.components, MsiComponentRow::fits, &mut t),
            registry: capped(&self.registry, MsiRegistryRaw::fits, &mut t),
            remove_registry: capped(&self.remove_registry, MsiRegistryRaw::fits, &mut t),
            classes: capped(&self.classes, MsiClassRow::fits, &mut t),
            progids: capped(&self.progids, str_fits, &mut t),
            extensions: capped(&self.extensions, MsiExtensionRow::fits, &mut t),
            typelibs: capped(&self.typelibs, str_fits, &mut t),
            appids: capped(&self.appids, str_fits, &mut t),
            service_install: capped(&self.service_install, MsiServiceRaw::fits, &mut t),
            custom_action_count: self.custom_action_count,
            truncated: t,
        }
    }

    /// The number of rows over all tables (`CustomAction` not included).
    pub fn row_count(&self) -> usize {
        self.properties.len()
            + self.components.len()
            + self.registry.len()
            + self.remove_registry.len()
            + self.classes.len()
            + self.progids.len()
            + self.extensions.len()
            + self.typelibs.len()
            + self.appids.len()
            + self.service_install.len()
    }
}

/// `tasks` when there are at most [`MAX_TASKS`], otherwise `SourceError::Other(`[`TOO_MANY_TASKS`]`)`.
pub fn limited_tasks(tasks: &[TaskInfo]) -> SourceResult<Vec<TaskInfo>> {
    if tasks.len() > MAX_TASKS {
        return Err(SourceError::Other(TOO_MANY_TASKS));
    }
    Ok(tasks.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limited_keeps_tables_within_the_limits_unchanged() {
        let t = MsiTables {
            properties: vec![("ProductName".into(), "App".into())],
            components: vec![MsiComponentRow {
                component: "Main".into(),
                component_id: Some("{11111111-2222-3333-4444-555555555555}".into()),
                attributes: 256,
                key_path: Some("app.exe".into()),
            }],
            custom_action_count: 3,
            ..MsiTables::default()
        };
        assert_eq!(t.limited(), t);
        assert_eq!(t.row_count(), 2);
    }

    #[test]
    fn a_cell_over_the_limit_drops_its_row_and_sets_truncated() {
        let long = "k".repeat(MAX_CELL_BYTES + 1);
        let fits = "k".repeat(MAX_CELL_BYTES);
        let row = |key: &str| MsiRegistryRaw {
            row: "r".into(),
            root: 2,
            key: key.into(),
            name: None,
            value: None,
            component: "c".into(),
        };
        let t = MsiTables {
            registry: vec![row(&fits), row(&long), row("Software\\Vendor")],
            progids: vec![long.clone()],
            ..MsiTables::default()
        };
        let l = t.limited();
        assert!(l.truncated);
        assert_eq!(l.registry, vec![row(&fits), row("Software\\Vendor")]);
        assert!(l.progids.is_empty());
    }

    #[test]
    fn too_many_tasks_is_an_error_not_a_cut_list() {
        let tasks = vec![TaskInfo::default(); MAX_TASKS];
        assert_eq!(limited_tasks(&tasks).map(|t| t.len()), Ok(MAX_TASKS));
        let tasks = vec![TaskInfo::default(); MAX_TASKS + 1];
        assert_eq!(
            limited_tasks(&tasks),
            Err(SourceError::Other(TOO_MANY_TASKS))
        );
    }
}
