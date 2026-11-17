//! Live implementation of the two M1b [`SystemSource`](crate::system::SystemSource) methods over
//! `purge-win` (C-SOURCE, C-WIN): the MSI tables of one cached package (`msi_db::read_tables`) and the
//! scheduled tasks (`taskschd::list_all`).
//!
//! `purge-win` does not depend on `purge-model`, so each wrapper has its own error and row types; this
//! module maps them onto [`SourceError`], [`MsiTables`] and [`TaskInfo`].
//!
//! # Errors
//!
//! A failure is always an error, never an empty table set or an empty task list:
//!
//! - "file not found" and "path not found" (`ERROR_FILE_NOT_FOUND`, `ERROR_PATH_NOT_FOUND`, or their
//!   `HRESULT` forms) are [`SourceError::NotFound`]; access denied is [`SourceError::AccessDenied`];
//!   anything else is [`SourceError::Other`] with the Win32 code (an `HRESULT` that does not wrap one is
//!   kept whole).
//! - `MsiOpenDatabaseW` reports a package that is not there with a generic open failure, not with
//!   `ERROR_FILE_NOT_FOUND`. When the open fails with any code other than access denied, the package path
//!   is probed with [`FileSystemSource::exists`]: only a proven absence (`Absent`: not found on a mounted
//!   fixed NTFS/ReFS volume, no reparse point on the path) makes the error `NotFound`; otherwise the open
//!   failure's code is kept (`Other`).
//! - A `LocalPackage` that is not an absolute drive or UNC path is [`SourceError::InvalidPath`], as in
//!   the fixture.
//! - A task list over [`MAX_TASKS`] or deeper than the wrapper's folder cap is
//!   `Other(`[`TOO_MANY_TASKS`]`)`: a list that cannot be complete is never returned cut.
//!
//! # Limits
//!
//! `read_tables` caps rows per table and UTF-16 units per cell; the result then goes through
//! [`MsiTables::limited`], which applies the C-SOURCE limits in UTF-8 bytes (a cell within the wrapper's
//! 65,536 units can still be over 64 KiB in UTF-8) and keeps the wrapper's `truncated` flag.
//!
//! # Tasks
//!
//! A task the wrapper flags unreadable is returned with an empty action list (what C-SOURCE calls a task
//! the scanning user cannot read); its definition fields are unknown. `stored_password` is `true` when the
//! logon type may hold a stored password (`Password`, `InteractiveTokenOrPassword`, a type this build does
//! not know) **or is unknown** (an unreadable task): the cautious answer, since a stored password makes a
//! task impossible to register again.
//!
//! # Threads
//!
//! Each call opens its own MSI database handle, or enters (and leaves) the COM apartment on the calling
//! thread for its own duration; nothing is shared between calls, so both may run on several threads at
//! once.

use std::path::Path;

use purge_model::object::{TaskAction, TaskIdentity};
use purge_win::msi_db::{self, RawTables, TableLimits};
use purge_win::taskschd::{self, LogonType, RawAction, RawTask};

use super::errors::hresult_code;
use super::filesystem::LiveFileSystem;
use crate::filesystem::FileSystemSource;
use crate::sysobj::{
    MsiClassRow, MsiComponentRow, MsiExtensionRow, MsiRegistryRaw, MsiServiceRaw, MsiTables,
    TOO_MANY_TASKS, TaskInfo, limited_tasks,
};
use crate::types::{ExistsState, SourceError, SourceResult};

/// `ERROR_FILE_NOT_FOUND`.
const ERROR_FILE_NOT_FOUND: u32 = 2;
/// `ERROR_PATH_NOT_FOUND`.
const ERROR_PATH_NOT_FOUND: u32 = 3;
/// `ERROR_ACCESS_DENIED`.
const ERROR_ACCESS_DENIED: u32 = 5;
/// `ERROR_INVALID_DATA`: text that is not valid UTF-16.
const ERROR_INVALID_DATA: u32 = 13;
/// `ERROR_INVALID_PARAMETER`: a wrapper refusal that `list_all` never produces.
const ERROR_INVALID_PARAMETER: u32 = 87;

/// The C-SOURCE error rule for a Win32 code: not found, access denied, or `Other(code)`.
fn map_code(code: u32) -> SourceError {
    match code {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => SourceError::NotFound,
        ERROR_ACCESS_DENIED => SourceError::AccessDenied,
        other => SourceError::Other(other),
    }
}

// ---------------------------------------------------------------------------------------------------------
// MSI tables
// ---------------------------------------------------------------------------------------------------------

/// The tables of the cached package at `local_package`, within the C-SOURCE limits.
pub(crate) fn msi_tables(local_package: &str) -> SourceResult<MsiTables> {
    match msi_db::read_tables(Path::new(local_package), &TableLimits::DEFAULT) {
        Ok(raw) => Ok(to_tables(raw)),
        Err(e) => Err(map_msi_error(local_package, e, |p| {
            LiveFileSystem::default().exists(p)
        })),
    }
}

/// Maps a `read_tables` error. `exists` probes the package path; it is called only for an open failure
/// whose code is neither "not found" nor "access denied".
fn map_msi_error(
    local_package: &str,
    e: msi_db::WinError,
    exists: impl FnOnce(&str) -> ExistsState,
) -> SourceError {
    match e {
        msi_db::WinError::InvalidPath(_) => SourceError::InvalidPath(local_package.to_string()),
        msi_db::WinError::Open(err) => match map_code(err.code()) {
            SourceError::Other(code) => match exists(local_package) {
                ExistsState::Absent => SourceError::NotFound,
                ExistsState::Present | ExistsState::Unknown => SourceError::Other(code),
            },
            mapped => mapped,
        },
        msi_db::WinError::Table { error, .. } => map_code(error.code()),
    }
}

/// The wrapper's rows as [`MsiTables`], then [`MsiTables::limited`].
fn to_tables(raw: RawTables) -> MsiTables {
    MsiTables {
        properties: raw.properties,
        components: raw
            .components
            .into_iter()
            .map(|r| MsiComponentRow {
                component: r.component,
                component_id: r.component_id,
                attributes: r.attributes,
                key_path: r.key_path,
            })
            .collect(),
        registry: raw.registry.into_iter().map(to_registry_row).collect(),
        remove_registry: raw
            .remove_registry
            .into_iter()
            .map(to_registry_row)
            .collect(),
        classes: raw
            .classes
            .into_iter()
            .map(|r| MsiClassRow {
                clsid: r.clsid,
                context: r.context,
                component: r.component,
                progid: r.progid,
                appid: r.appid,
            })
            .collect(),
        progids: raw.progids,
        extensions: raw
            .extensions
            .into_iter()
            .map(|r| MsiExtensionRow {
                extension: r.extension,
                component: r.component,
                progid: r.progid,
            })
            .collect(),
        typelibs: raw.typelibs,
        appids: raw.appids,
        service_install: raw
            .service_install
            .into_iter()
            .map(|r| MsiServiceRaw {
                name: r.name,
                component: r.component,
                service_type: r.service_type,
                start_type: r.start_type,
            })
            .collect(),
        custom_action_count: raw.custom_action_count,
        truncated: raw.truncated,
    }
    .limited()
}

fn to_registry_row(r: msi_db::RegistryRow) -> MsiRegistryRaw {
    MsiRegistryRaw {
        row: r.row,
        root: r.root,
        key: r.key,
        name: r.name,
        value: r.value,
        component: r.component,
    }
}

// ---------------------------------------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------------------------------------

/// Every scheduled task the engine's account can see.
pub(crate) fn tasks() -> SourceResult<Vec<TaskInfo>> {
    let raw = taskschd::list_all().map_err(map_task_error)?;
    let tasks: Vec<TaskInfo> = raw.into_iter().map(to_task_info).collect();
    limited_tasks(&tasks)
}

/// Maps a `list_all` error.
fn map_task_error(e: taskschd::WinError) -> SourceError {
    match e {
        taskschd::WinError::Com { hresult, .. } => map_code(hresult_code(hresult as i32)),
        taskschd::WinError::TooManyTasks { .. } | taskschd::WinError::TooDeep { .. } => {
            SourceError::Other(TOO_MANY_TASKS)
        }
        taskschd::WinError::InvalidUtf16 { .. } => SourceError::Other(ERROR_INVALID_DATA),
        _ => SourceError::Other(ERROR_INVALID_PARAMETER),
    }
}

/// One wrapper task as [`TaskInfo`]. An unreadable task keeps an empty action list.
fn to_task_info(raw: RawTask) -> TaskInfo {
    let actions = if raw.unreadable {
        Vec::new()
    } else {
        raw.actions.into_iter().map(to_action).collect()
    };
    TaskInfo {
        identity: TaskIdentity {
            path: raw.path,
            actions,
        },
        enabled: raw.enabled,
        hidden: raw.hidden,
        author: raw.author,
        stored_password: raw.logon_type.is_none_or(LogonType::may_store_password),
        run_as: raw.user_id,
    }
}

fn to_action(a: RawAction) -> TaskAction {
    match a {
        RawAction::Exec {
            path,
            arguments,
            working_dir,
        } => TaskAction::Exec {
            path,
            arguments,
            working_dir,
        },
        RawAction::ComHandler { clsid, data } => TaskAction::ComHandler { clsid, data },
        RawAction::Other { kind } => TaskAction::Other { kind },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysobj::MAX_CELL_BYTES;
    use purge_win::os::Win32Error;

    const PKG: &str = r"C:\Windows\Installer\1a2b3c.msi";

    fn never(_: &str) -> ExistsState {
        panic!("the path must not be probed for this error")
    }

    #[test]
    fn msi_open_errors_map_by_code_then_by_probe() {
        let open = |code| msi_db::WinError::Open(Win32Error(code));
        // Direct codes: no probe.
        assert_eq!(map_msi_error(PKG, open(2), never), SourceError::NotFound);
        assert_eq!(map_msi_error(PKG, open(3), never), SourceError::NotFound);
        assert_eq!(
            map_msi_error(PKG, open(5), never),
            SourceError::AccessDenied
        );
        // A generic open failure: NotFound only on a proven absence.
        assert_eq!(
            map_msi_error(PKG, open(110), |_| ExistsState::Absent),
            SourceError::NotFound
        );
        assert_eq!(
            map_msi_error(PKG, open(110), |_| ExistsState::Present),
            SourceError::Other(110)
        );
        assert_eq!(
            map_msi_error(PKG, open(110), |_| ExistsState::Unknown),
            SourceError::Other(110)
        );
        assert_eq!(
            map_msi_error(PKG, open(32), |_| ExistsState::Present),
            SourceError::Other(32)
        );
        // The probe gets the package path as given.
        let mut probed = String::new();
        let _ = map_msi_error(PKG, open(1620), |p| {
            probed = p.to_string();
            ExistsState::Present
        });
        assert_eq!(probed, PKG);
    }

    #[test]
    fn msi_table_and_path_errors_map_without_probe() {
        let table = |code| msi_db::WinError::Table {
            table: "Registry",
            step: "MsiViewFetch",
            error: Win32Error(code),
        };
        assert_eq!(
            map_msi_error(PKG, table(5), never),
            SourceError::AccessDenied
        );
        assert_eq!(map_msi_error(PKG, table(2), never), SourceError::NotFound);
        assert_eq!(
            map_msi_error(PKG, table(1627), never),
            SourceError::Other(1627)
        );
        assert_eq!(
            map_msi_error(
                "a.msi",
                msi_db::WinError::InvalidPath("a.msi".into()),
                never
            ),
            SourceError::InvalidPath("a.msi".into())
        );
    }

    #[test]
    fn task_errors_map() {
        let com = |hresult| taskschd::WinError::Com {
            step: "ITaskService::Connect",
            hresult,
        };
        assert_eq!(map_task_error(com(0x8007_0005)), SourceError::AccessDenied);
        assert_eq!(map_task_error(com(0x8007_0002)), SourceError::NotFound);
        assert_eq!(map_task_error(com(0x8007_0003)), SourceError::NotFound);
        assert_eq!(map_task_error(com(0x8007_06BA)), SourceError::Other(0x6BA));
        assert_eq!(
            map_task_error(com(0x8004_1311)),
            SourceError::Other(0x8004_1311)
        );
        assert_eq!(
            map_task_error(taskschd::WinError::TooManyTasks { max: 20_000 }),
            SourceError::Other(TOO_MANY_TASKS)
        );
        assert_eq!(
            map_task_error(taskschd::WinError::TooDeep {
                path: r"\a".into(),
                max: 32
            }),
            SourceError::Other(TOO_MANY_TASKS)
        );
        assert_eq!(
            map_task_error(taskschd::WinError::InvalidUtf16 { step: "x" }),
            SourceError::Other(ERROR_INVALID_DATA)
        );
    }

    fn raw_task(unreadable: bool) -> RawTask {
        RawTask {
            path: r"\Vendor\Update".into(),
            enabled: true,
            running: Some(false),
            hidden: true,
            actions: vec![
                RawAction::Exec {
                    path: r"C:\Program Files\App\u.exe".into(),
                    arguments: Some("/q".into()),
                    working_dir: None,
                },
                RawAction::ComHandler {
                    clsid: "{11111111-2222-3333-4444-555555555555}".into(),
                    data: None,
                },
                RawAction::Other {
                    kind: "send_email".into(),
                },
            ],
            logon_type: Some(LogonType::InteractiveToken),
            user_id: Some("tester".into()),
            author: Some("Vendor".into()),
            unreadable,
        }
    }

    #[test]
    fn task_maps_every_field() {
        let t = to_task_info(raw_task(false));
        assert_eq!(t.identity.path, r"\Vendor\Update");
        assert_eq!(
            t.identity.actions,
            vec![
                TaskAction::Exec {
                    path: r"C:\Program Files\App\u.exe".into(),
                    arguments: Some("/q".into()),
                    working_dir: None,
                },
                TaskAction::ComHandler {
                    clsid: "{11111111-2222-3333-4444-555555555555}".into(),
                    data: None,
                },
                TaskAction::Other {
                    kind: "send_email".into()
                },
            ]
        );
        assert!(t.enabled && t.hidden && !t.stored_password);
        assert_eq!(t.author.as_deref(), Some("Vendor"));
        assert_eq!(t.run_as.as_deref(), Some("tester"));
    }

    #[test]
    fn unreadable_task_is_kept_with_no_actions() {
        // The wrapper never sets actions on an unreadable task; even if it did, none are taken.
        let mut raw = raw_task(true);
        raw.logon_type = None;
        raw.author = None;
        raw.user_id = None;
        let t = to_task_info(raw);
        assert_eq!(t.identity.path, r"\Vendor\Update");
        assert!(t.identity.actions.is_empty());
        // Unknown logon type: the cautious answer.
        assert!(t.stored_password);
    }

    #[test]
    fn stored_password_follows_the_logon_type() {
        for (logon, stored) in [
            (LogonType::None, false),
            (LogonType::S4u, false),
            (LogonType::InteractiveToken, false),
            (LogonType::Group, false),
            (LogonType::ServiceAccount, false),
            (LogonType::Password, true),
            (LogonType::InteractiveTokenOrPassword, true),
            (LogonType::Other(9), true),
        ] {
            let mut raw = raw_task(false);
            raw.logon_type = Some(logon);
            assert_eq!(to_task_info(raw).stored_password, stored, "{logon:?}");
        }
    }

    #[test]
    fn tables_map_and_apply_the_utf8_cell_limit() {
        // 30,000 three-byte characters: within the wrapper's 65,536 UTF-16 units, over 64 KiB of UTF-8.
        let wide_cell = "\u{20AC}".repeat(30_000);
        assert!(wide_cell.len() > MAX_CELL_BYTES);
        let raw = RawTables {
            properties: vec![("ProductName".into(), "App".into())],
            components: vec![msi_db::ComponentRow {
                component: "Main".into(),
                component_id: Some("{AAAAAAAA-0000-0000-0000-000000000001}".into()),
                attributes: 256,
                key_path: Some("app.exe".into()),
            }],
            registry: vec![
                msi_db::RegistryRow {
                    row: "r1".into(),
                    root: 2,
                    key: r"Software\[Manufacturer]".into(),
                    name: Some("[VALNAME]".into()),
                    value: Some("#1".into()),
                    component: "Main".into(),
                },
                msi_db::RegistryRow {
                    row: "r2".into(),
                    root: 2,
                    key: wide_cell,
                    name: None,
                    value: None,
                    component: "Main".into(),
                },
            ],
            remove_registry: vec![msi_db::RegistryRow {
                row: "rr".into(),
                root: -1,
                key: r"Software\Old".into(),
                name: Some("-".into()),
                value: None,
                component: "Main".into(),
            }],
            classes: vec![msi_db::ClassRow {
                clsid: "{BBBBBBBB-0000-0000-0000-000000000001}".into(),
                context: "InprocServer32".into(),
                component: "Main".into(),
                progid: None,
                appid: Some("{CC}".into()),
            }],
            progids: vec!["App.Doc".into()],
            extensions: vec![msi_db::ExtensionRow {
                extension: "adoc".into(),
                component: "Main".into(),
                progid: Some("App.Doc".into()),
            }],
            typelibs: vec!["{DD}".into()],
            appids: vec!["{CC}".into()],
            service_install: vec![msi_db::ServiceInstallRow {
                name: "AppSvc".into(),
                component: "Main".into(),
                service_type: 16,
                start_type: 3,
            }],
            custom_action_count: 4,
            truncated: false,
        };
        let t = to_tables(raw);
        assert!(t.truncated, "the over-long row is dropped and counted");
        assert_eq!(t.registry.len(), 1);
        assert_eq!(t.registry[0].row, "r1");
        assert_eq!(t.registry[0].name.as_deref(), Some("[VALNAME]"));
        assert_eq!(t.remove_registry[0].root, -1);
        assert_eq!(t.remove_registry[0].value, None);
        assert_eq!(t.components[0].attributes, 256);
        assert_eq!(t.classes[0].appid.as_deref(), Some("{CC}"));
        assert_eq!(t.extensions[0].progid.as_deref(), Some("App.Doc"));
        assert_eq!(t.service_install[0].start_type, 3);
        assert_eq!(t.custom_action_count, 4);
        assert_eq!(
            (t.progids.len(), t.typelibs.len(), t.appids.len()),
            (1, 1, 1)
        );

        // The wrapper's own truncation is kept.
        let flagged = to_tables(RawTables {
            truncated: true,
            ..RawTables::default()
        });
        assert!(flagged.truncated);
        assert_eq!(to_tables(RawTables::default()), MsiTables::default());
    }
}
