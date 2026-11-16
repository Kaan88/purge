//! Read-only MSI database access: open a package and run table queries (M1b).
//!
//! ENGINE_PLAN.md §5.5 and the C-WIN contract (docs/M1B_DESIGN.json). [`read_tables`] opens one `.msi`
//! file (normally a product's cached `LocalPackage` under `%WINDIR%\Installer`) with
//! `MsiOpenDatabaseW(path, MSIDBOPEN_READONLY)` and returns the rows the ownership index needs:
//! `Property` (a fixed set plus the properties the `Registry` / `RemoveRegistry` rows reference),
//! `Component`, `Registry`, `RemoveRegistry`, `Class`, `ProgId`, `Extension`, `TypeLib`, `AppId`,
//! `ServiceInstall`, and the row count of `CustomAction`.
//!
//! What this module never does: it never opens an installer session on a package or a product, never
//! sets the installer UI level, and never calls anything that can install, configure, reinstall or
//! repair. The only `msi.dll` entry points used are the database, view and record functions below.
//!
//! Hostile or broken files:
//! - the path is used exactly as given; a relative path, a device path or a path with a NUL is
//!   refused before `msi.dll` sees it;
//! - a file that is not an MSI database gives [`WinError::Open`];
//! - a table that does not exist gives an empty list; any other failure on a table (a missing
//!   column, a failed fetch) gives `Err` for the whole package, so partial tables never look
//!   complete;
//! - [`TableLimits`] caps rows per table and UTF-16 units per cell. Rows past `max_rows` are not read
//!   and set [`RawTables::truncated`]; a row with a cell over `max_cell` is dropped whole and also
//!   sets `truncated`. The caller treats a truncated package as unreadable;
//! - every `MSIHANDLE` (database, view, record) is owned by a guard that closes it on every path.
//!
//! Cell conventions: Windows Installer stores an empty string as null, so a null text cell in an
//! optional column is `None` and in a required column the empty string. A null integer cell reads as
//! `i32::MIN` (`MSI_NULL_INTEGER`), which no valid `Root`, `Attributes`, `ServiceType` or `StartType`
//! value can be. Formatted cells (`Registry.Key` and the like) are returned unresolved.
#![cfg(feature = "read")]

use std::collections::BTreeSet;
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, Prefix};

use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::ApplicationInstallationAndServicing::{
    MSICONDITION_FALSE, MSICONDITION_NONE, MSICONDITION_TRUE, MSIDBOPEN_READONLY, MSIHANDLE,
    MsiCloseHandle, MsiDatabaseIsTablePersistentW, MsiDatabaseOpenViewW, MsiOpenDatabaseW,
    MsiRecordGetInteger, MsiRecordGetStringW, MsiRecordIsNull, MsiViewExecute, MsiViewFetch,
};

use crate::os::{Win32Error, wide};

/// Per-table limits applied by [`read_tables`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableLimits {
    /// Rows read per table. A table with more rows sets [`RawTables::truncated`].
    pub max_rows: usize,
    /// UTF-16 code units per text cell. A row with a longer cell is dropped and sets
    /// [`RawTables::truncated`].
    pub max_cell: usize,
}

impl TableLimits {
    /// The limits of the C-SOURCE contract: 200,000 rows per table, 65,536 units per cell.
    pub const DEFAULT: TableLimits = TableLimits {
        max_rows: 200_000,
        max_cell: 65_536,
    };
}

impl Default for TableLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A `Component` row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComponentRow {
    /// `Component` (primary key).
    pub component: String,
    /// `ComponentId` (a GUID); `None` for a component the installer does not register.
    pub component_id: Option<String>,
    /// `Attributes`.
    pub attributes: i32,
    /// `KeyPath`: a `File`, `Registry` or `ODBCDataSource` key, or `None` for the directory.
    pub key_path: Option<String>,
}

/// A `Registry` or `RemoveRegistry` row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryRow {
    /// `Registry` / `RemoveRegistry` (primary key).
    pub row: String,
    /// `Root`: -1, 0 (HKCR), 1 (HKCU), 2 (HKLM), 3 (HKU) in a valid package.
    pub root: i32,
    /// `Key`, Formatted and unresolved.
    pub key: String,
    /// `Name`, unchanged: `+`, `-` and `*` (whole-key markers) are kept as they are.
    pub name: Option<String>,
    /// `Value`; always `None` for `RemoveRegistry`, which has no such column.
    pub value: Option<String>,
    /// `Component_`.
    pub component: String,
}

/// A `Class` row (the columns ownership needs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClassRow {
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

/// An `Extension` row (the columns ownership needs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtensionRow {
    /// `Extension`, without the leading dot.
    pub extension: String,
    /// `Component_`.
    pub component: String,
    /// `ProgId_`.
    pub progid: Option<String>,
}

/// A `ServiceInstall` row (the columns ownership needs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceInstallRow {
    /// `Name`, Formatted and unresolved.
    pub name: String,
    /// `Component_`.
    pub component: String,
    /// `ServiceType`.
    pub service_type: i32,
    /// `StartType`.
    pub start_type: i32,
}

/// The tables [`read_tables`] returns. A table the package does not have is an empty list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawTables {
    /// `(Property, Value)` for [`FIXED_PROPERTIES`] and for every property referenced as `[Name]` in a
    /// `Registry` or `RemoveRegistry` `Key` or `Name` cell, in table order. A null value is `""`.
    pub properties: Vec<(String, String)>,
    /// `Component`.
    pub components: Vec<ComponentRow>,
    /// `Registry`.
    pub registry: Vec<RegistryRow>,
    /// `RemoveRegistry`.
    pub remove_registry: Vec<RegistryRow>,
    /// `Class`.
    pub classes: Vec<ClassRow>,
    /// `ProgId.ProgId`.
    pub progids: Vec<String>,
    /// `Extension`.
    pub extensions: Vec<ExtensionRow>,
    /// `TypeLib.LibID`.
    pub typelibs: Vec<String>,
    /// `AppId.AppId`.
    pub appids: Vec<String>,
    /// `ServiceInstall`.
    pub service_install: Vec<ServiceInstallRow>,
    /// Rows in `CustomAction` (at most `max_rows`).
    pub custom_action_count: u32,
    /// A table had more than `max_rows` rows, or a row was dropped for a cell over `max_cell`.
    pub truncated: bool,
}

/// The properties [`read_tables`] always returns when the package defines them.
pub const FIXED_PROPERTIES: [&str; 7] = [
    "ProductCode",
    "UpgradeCode",
    "ProductName",
    "ProductVersion",
    "Manufacturer",
    "ALLUSERS",
    "ARPINSTALLLOCATION",
];

/// Why [`read_tables`] failed. Any error means the package is unreadable as a whole.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WinError {
    /// The path is not an absolute drive-letter or UNC path, or it contains a NUL.
    #[error("not an absolute drive or UNC path: {0}")]
    InvalidPath(String),
    /// `MsiOpenDatabaseW` refused the file (missing, not an MSI database, access denied, ...).
    #[error("cannot open MSI database: {0}")]
    Open(Win32Error),
    /// A table that exists could not be read in full.
    #[error("cannot read MSI table {table} ({step}): {error}")]
    Table {
        /// The table.
        table: &'static str,
        /// The call that failed.
        step: &'static str,
        /// Its error code.
        error: Win32Error,
    },
}

/// Owns one `MSIHANDLE` and closes it on drop. A zero handle (nothing opened) is not closed.
struct MsiHandle(MSIHANDLE);

impl Drop for MsiHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: the handle was returned by msi.dll, is owned by this guard alone and is closed
            // exactly once.
            unsafe { MsiCloseHandle(self.0) };
        }
    }
}

/// Reads the tables of one MSI database, read-only. See the module documentation for the rules.
pub fn read_tables(local_package: &Path, limits: &TableLimits) -> Result<RawTables, WinError> {
    let path = path_arg(local_package)?;
    let mut raw: MSIHANDLE = 0;
    // SAFETY: `path` is NUL-terminated; MSIDBOPEN_READONLY is a predefined persist mode, not a
    // pointer; `raw` is a valid out-pointer.
    let rc = unsafe { MsiOpenDatabaseW(path.as_ptr(), MSIDBOPEN_READONLY, &mut raw) };
    let db = MsiHandle(raw);
    if rc != ERROR_SUCCESS {
        return Err(WinError::Open(Win32Error(rc)));
    }
    if db.0 == 0 {
        return Err(WinError::Open(Win32Error::INVALID_DATA));
    }

    let mut t = Reader {
        db: &db,
        limits,
        truncated: false,
    };
    let registry = t.registry("Registry", true)?;
    let remove_registry = t.registry("RemoveRegistry", false)?;
    let wanted = wanted_properties(registry.iter().chain(&remove_registry));
    let properties = t.read("Property", &["Property", "Value"], |r| {
        let Some(name) = r.required(1)? else {
            return Ok(None);
        };
        let Some(value) = r.required(2)? else {
            return Ok(None);
        };
        Ok(Some((name, value)))
    })?;
    let properties = properties
        .into_iter()
        .filter(|(name, _)| wanted.contains(name.as_str()))
        .collect();
    let components = t.read(
        "Component",
        &["Component", "ComponentId", "Attributes", "KeyPath"],
        |r| {
            let Some(component) = r.required(1)? else {
                return Ok(None);
            };
            let Some(component_id) = r.optional(2)? else {
                return Ok(None);
            };
            let attributes = r.int(3);
            let Some(key_path) = r.optional(4)? else {
                return Ok(None);
            };
            Ok(Some(ComponentRow {
                component,
                component_id,
                attributes,
                key_path,
            }))
        },
    )?;
    let classes = t.read(
        "Class",
        &["CLSID", "Context", "Component_", "ProgId_Default", "AppId_"],
        |r| {
            let Some(clsid) = r.required(1)? else {
                return Ok(None);
            };
            let Some(context) = r.required(2)? else {
                return Ok(None);
            };
            let Some(component) = r.required(3)? else {
                return Ok(None);
            };
            let Some(progid) = r.optional(4)? else {
                return Ok(None);
            };
            let Some(appid) = r.optional(5)? else {
                return Ok(None);
            };
            Ok(Some(ClassRow {
                clsid,
                context,
                component,
                progid,
                appid,
            }))
        },
    )?;
    let progids = t.read("ProgId", &["ProgId"], |r| r.required(1))?;
    let extensions = t.read("Extension", &["Extension", "Component_", "ProgId_"], |r| {
        let Some(extension) = r.required(1)? else {
            return Ok(None);
        };
        let Some(component) = r.required(2)? else {
            return Ok(None);
        };
        let Some(progid) = r.optional(3)? else {
            return Ok(None);
        };
        Ok(Some(ExtensionRow {
            extension,
            component,
            progid,
        }))
    })?;
    let typelibs = t.read("TypeLib", &["LibID"], |r| r.required(1))?;
    let appids = t.read("AppId", &["AppId"], |r| r.required(1))?;
    let service_install = t.read(
        "ServiceInstall",
        &["Name", "Component_", "ServiceType", "StartType"],
        |r| {
            let Some(name) = r.required(1)? else {
                return Ok(None);
            };
            let Some(component) = r.required(2)? else {
                return Ok(None);
            };
            Ok(Some(ServiceInstallRow {
                name,
                component,
                service_type: r.int(3),
                start_type: r.int(4),
            }))
        },
    )?;
    // Only the count matters: the key column is selected but never copied out of the record.
    let custom_actions = t.read("CustomAction", &["Action"], |_| Ok(Some(())))?;
    let custom_action_count = u32::try_from(custom_actions.len()).unwrap_or(u32::MAX);

    Ok(RawTables {
        properties,
        components,
        registry,
        remove_registry,
        classes,
        progids,
        extensions,
        typelibs,
        appids,
        service_install,
        custom_action_count,
        truncated: t.truncated,
    })
}

/// The path as a NUL-terminated wide string, or `InvalidPath` unless it is an absolute drive-letter
/// or UNC path (plain or `\\?\`) without NULs. No search, expansion or current-directory fallback.
fn path_arg(path: &Path) -> Result<Vec<u16>, WinError> {
    let invalid = || WinError::InvalidPath(path.display().to_string());
    let supported = match path.components().next() {
        Some(Component::Prefix(p)) => matches!(
            p.kind(),
            Prefix::Disk(_) | Prefix::VerbatimDisk(_) | Prefix::UNC(..) | Prefix::VerbatimUNC(..)
        ),
        _ => false,
    };
    if !supported || !path.is_absolute() || path.as_os_str().encode_wide().any(|c| c == 0) {
        return Err(invalid());
    }
    Ok(wide(path))
}

/// The property names to return: the fixed set plus every `[Name]` reference in a `Key` or `Name`
/// cell of the given rows.
fn wanted_properties<'a>(rows: impl Iterator<Item = &'a RegistryRow>) -> BTreeSet<&'a str> {
    let mut wanted: BTreeSet<&str> = FIXED_PROPERTIES.into_iter().collect();
    for row in rows {
        property_refs(&row.key, &mut wanted);
        if let Some(name) = &row.name {
            property_refs(name, &mut wanted);
        }
    }
    wanted
}

/// Adds every `[Name]` in a Formatted string whose content is a property identifier (a letter or `_`,
/// then letters, digits, `_` or `.`). `[#file]`, `[$component]`, `[%ENV]`, `[\x]` and `[~]` are not
/// properties. With nested brackets the innermost pair counts.
fn property_refs<'a>(formatted: &'a str, out: &mut BTreeSet<&'a str>) {
    let mut open: Option<usize> = None;
    for (i, c) in formatted.char_indices() {
        match c {
            '[' => open = Some(i + 1),
            ']' => {
                let inner = open.take().and_then(|start| formatted.get(start..i));
                if let Some(inner) = inner.filter(|s| is_property_name(s)) {
                    out.insert(inner);
                }
            }
            _ => {}
        }
    }
}

fn is_property_name(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

/// Reads tables of one open database and remembers whether any limit was hit.
struct Reader<'a> {
    db: &'a MsiHandle,
    limits: &'a TableLimits,
    truncated: bool,
}

impl Reader<'_> {
    /// `Registry` (with `Value`) or `RemoveRegistry` (without).
    fn registry(
        &mut self,
        table: &'static str,
        with_value: bool,
    ) -> Result<Vec<RegistryRow>, WinError> {
        let columns: &[&str] = if with_value {
            &[table, "Root", "Key", "Name", "Value", "Component_"]
        } else {
            &[table, "Root", "Key", "Name", "Component_"]
        };
        self.read(table, columns, |r| {
            let Some(row) = r.required(1)? else {
                return Ok(None);
            };
            let root = r.int(2);
            let Some(key) = r.required(3)? else {
                return Ok(None);
            };
            let Some(name) = r.optional(4)? else {
                return Ok(None);
            };
            let (value, component_field) = if with_value {
                let Some(value) = r.optional(5)? else {
                    return Ok(None);
                };
                (value, 6)
            } else {
                (None, 5)
            };
            let Some(component) = r.required(component_field)? else {
                return Ok(None);
            };
            Ok(Some(RegistryRow {
                row,
                root,
                key,
                name,
                value,
                component,
            }))
        })
    }

    /// Runs `SELECT columns FROM table` and maps each row. The mapper returns `Ok(None)` for a row
    /// with a cell over the limit; the row is dropped and `truncated` set. A missing table is an empty
    /// list; any other failure is an error.
    fn read<T>(
        &mut self,
        table: &'static str,
        columns: &[&str],
        mut map: impl FnMut(&Row<'_>) -> Result<Option<T>, WinError>,
    ) -> Result<Vec<T>, WinError> {
        if !self.table_exists(table)? {
            return Ok(Vec::new());
        }
        let fail = |step: &'static str, rc: u32| WinError::Table {
            table,
            step,
            error: Win32Error(rc),
        };
        let column_list = columns
            .iter()
            .map(|c| format!("`{c}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let query = wide(format!("SELECT {column_list} FROM `{table}`"));
        let mut raw: MSIHANDLE = 0;
        // SAFETY: the database handle is open; `query` is NUL-terminated; `raw` is a valid out-pointer.
        let rc = unsafe { MsiDatabaseOpenViewW(self.db.0, query.as_ptr(), &mut raw) };
        let view = MsiHandle(raw);
        if rc != ERROR_SUCCESS {
            return Err(fail("MsiDatabaseOpenViewW", rc));
        }
        // SAFETY: `view` is open; a zero record handle means no parameters.
        let rc = unsafe { MsiViewExecute(view.0, 0) };
        if rc != ERROR_SUCCESS {
            return Err(fail("MsiViewExecute", rc));
        }

        let mut out = Vec::new();
        let mut fetched = 0usize;
        loop {
            let mut raw: MSIHANDLE = 0;
            // SAFETY: `view` is open and executed; `raw` is a valid out-pointer.
            let rc = unsafe { MsiViewFetch(view.0, &mut raw) };
            let record = MsiHandle(raw);
            match rc {
                ERROR_SUCCESS => {}
                ERROR_NO_MORE_ITEMS => break,
                other => return Err(fail("MsiViewFetch", other)),
            }
            if fetched == self.limits.max_rows {
                // One row more than the limit exists: stop reading this table.
                self.truncated = true;
                break;
            }
            fetched += 1;
            let row = Row {
                record: &record,
                table,
                max_cell: self.limits.max_cell,
            };
            match map(&row)? {
                Some(item) => out.push(item),
                None => self.truncated = true,
            }
        }
        Ok(out)
    }

    /// Whether the table exists in the database (persistent or temporary).
    fn table_exists(&self, table: &'static str) -> Result<bool, WinError> {
        let name = wide(table);
        // SAFETY: the database handle is open and `name` is NUL-terminated.
        let cond = unsafe { MsiDatabaseIsTablePersistentW(self.db.0, name.as_ptr()) };
        match cond {
            MSICONDITION_TRUE | MSICONDITION_FALSE => Ok(true),
            MSICONDITION_NONE => Ok(false),
            _ => Err(WinError::Table {
                table,
                step: "MsiDatabaseIsTablePersistentW",
                error: Win32Error::INVALID_DATA,
            }),
        }
    }
}

/// One fetched record. Field numbers are 1-based, in the order of the SELECT column list.
struct Row<'a> {
    record: &'a MsiHandle,
    table: &'static str,
    max_cell: usize,
}

/// A text cell: `Ok(None)` is a cell over the limit, `Ok(Some(None))` a null cell.
type Cell = Result<Option<Option<String>>, WinError>;

impl Row<'_> {
    /// A column that should never be null: a null cell is the empty string (the installer stores ""
    /// as null). `Ok(None)` when the cell is over the limit.
    fn required(&self, field: u32) -> Result<Option<String>, WinError> {
        Ok(self.text(field)?.map(Option::unwrap_or_default))
    }

    /// A nullable column. `Ok(None)` when the cell is over the limit, `Ok(Some(None))` when null.
    fn optional(&self, field: u32) -> Cell {
        self.text(field)
    }

    /// An integer column; `i32::MIN` (`MSI_NULL_INTEGER`) for a null or non-numeric cell.
    fn int(&self, field: u32) -> i32 {
        // SAFETY: the record handle is open; an out-of-range field yields MSI_NULL_INTEGER.
        unsafe { MsiRecordGetInteger(self.record.0, field) }
    }

    fn text(&self, field: u32) -> Cell {
        // SAFETY: the record handle is open; an out-of-range field reads as null.
        if unsafe { MsiRecordIsNull(self.record.0, field) } != 0 {
            return Ok(Some(None));
        }
        let mut buf = vec![0u16; 256.min(self.max_cell.saturating_add(1)).max(1)];
        // Two attempts: the size answer of the first call is exact for a record, which cannot change.
        for _ in 0..2 {
            let mut len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
            // SAFETY: `buf` holds `len` UTF-16 units; the record handle is open.
            let rc =
                unsafe { MsiRecordGetStringW(self.record.0, field, buf.as_mut_ptr(), &mut len) };
            let len = len as usize;
            match rc {
                ERROR_SUCCESS => {
                    if len > self.max_cell {
                        return Ok(None);
                    }
                    let units = buf.get(..len.min(buf.len())).unwrap_or_default();
                    return Ok(Some(Some(String::from_utf16_lossy(units))));
                }
                ERROR_MORE_DATA => {
                    if len > self.max_cell {
                        return Ok(None);
                    }
                    buf = vec![0u16; len + 1];
                }
                other => {
                    return Err(WinError::Table {
                        table: self.table,
                        step: "MsiRecordGetStringW",
                        error: Win32Error(other),
                    });
                }
            }
        }
        Err(WinError::Table {
            table: self.table,
            step: "MsiRecordGetStringW",
            error: Win32Error::MORE_DATA,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_refs_take_identifiers_only() {
        let mut out = BTreeSet::new();
        property_refs(
            r"Software\[Manufacturer]\[ProductName.X]\[#file]\[$comp]\[%TEMP]\[\[]\[~]\[[INNER]]\[9bad]\[]\[OPEN",
            &mut out,
        );
        let got: Vec<&str> = out.into_iter().collect();
        assert_eq!(got, ["INNER", "Manufacturer", "ProductName.X"]);
    }

    #[test]
    fn path_arg_accepts_drive_and_unc_only() {
        for ok in [
            r"C:\Windows\Installer\1.msi",
            r"\\server\share\a.msi",
            r"\\?\C:\a.msi",
            r"\\?\UNC\server\share\a.msi",
        ] {
            assert!(path_arg(Path::new(ok)).is_ok(), "{ok}");
        }
        for bad in [
            "a.msi",
            r"C:a.msi",
            r"\a.msi",
            r"..\a.msi",
            r"\\.\pipe\a",
            r"\\?\GLOBALROOT\Device\a.msi",
            "",
        ] {
            assert!(
                matches!(path_arg(Path::new(bad)), Err(WinError::InvalidPath(_))),
                "{bad}"
            );
        }
        let with_nul = std::ffi::OsString::from("C:\\a\0b.msi");
        assert!(path_arg(Path::new(&with_nul)).is_err());
    }

    #[test]
    fn default_limits_match_contract() {
        assert_eq!(
            TableLimits::default(),
            TableLimits {
                max_rows: 200_000,
                max_cell: 65_536
            }
        );
    }
}
