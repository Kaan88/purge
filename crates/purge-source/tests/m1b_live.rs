//! Live system-object source tests (M1B-SOURCE-IMPL): `LiveSystem::msi_tables` over generated MSI
//! databases, `LiveSystem::tasks` over a task of the test's own, and the snapshot fixture's tasks and MSI
//! tables.
//!
//! Every MSI database is built by the test with `MsiOpenDatabaseW(CREATEDIRECT)` in a fresh directory
//! under `%TEMP%`, removed when the test ends. The task test registers one disabled task with no trigger
//! that cannot be started on demand (`\PurgeTest-<random>`, in the root folder so that nothing is left
//! once it is deleted) and deletes it again, also when the test fails.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use purge_model::object::TaskAction;
use purge_source::fixture::{Fixture, FixtureError};
use purge_source::live::LiveSystem;
use purge_source::snapfixture::msi_tables_file_for;
use purge_source::sysobj::{
    MAX_CELL_BYTES, MsiClassRow, MsiComponentRow, MsiExtensionRow, MsiRegistryRaw, MsiServiceRaw,
    MsiTables, TaskInfo,
};
use purge_source::system::SystemSource;
use purge_source::types::SourceError;

// ---------------------------------------------------------------------------------------------------------
// Scratch directory and MSI builder (msi.dll directly; the crate under test only reads)
// ---------------------------------------------------------------------------------------------------------

/// A unique directory under `std::env::temp_dir()`, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static N: AtomicU32 = AtomicU32::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "purge-source-m1b-{tag}-{}-{}-{nanos}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

type MsiHandle = u32;
const ERROR_SUCCESS: u32 = 0;
/// `MSIDBOPEN_CREATEDIRECT`: a predefined persist mode passed in the pointer argument.
const MSIDBOPEN_CREATEDIRECT: *const u16 = 4 as *const u16;

#[link(name = "msi", kind = "raw-dylib")]
unsafe extern "system" {
    fn MsiOpenDatabaseW(path: *const u16, persist: *const u16, out: *mut MsiHandle) -> u32;
    fn MsiDatabaseOpenViewW(db: MsiHandle, query: *const u16, out: *mut MsiHandle) -> u32;
    fn MsiViewExecute(view: MsiHandle, record: MsiHandle) -> u32;
    fn MsiViewClose(view: MsiHandle) -> u32;
    fn MsiDatabaseCommit(db: MsiHandle) -> u32;
    fn MsiCreateRecord(fields: u32) -> MsiHandle;
    fn MsiRecordSetStringW(record: MsiHandle, field: u32, value: *const u16) -> u32;
    fn MsiRecordSetInteger(record: MsiHandle, field: u32, value: i32) -> u32;
    fn MsiCloseHandle(h: MsiHandle) -> u32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

struct H(MsiHandle);

impl Drop for H {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: the handle is owned by this guard and closed once.
            unsafe { MsiCloseHandle(self.0) };
        }
    }
}

/// A cell of an insert.
#[derive(Clone, Copy)]
enum V<'a> {
    S(&'a str),
    I(i32),
}
use V::{I, S};

/// A database under construction; `finish` commits and closes it.
struct Db(H);

impl Db {
    fn create(path: &Path) -> Db {
        let p = wide(path.to_str().unwrap());
        let mut h: MsiHandle = 0;
        // SAFETY: NUL-terminated path, predefined persist mode, valid out-pointer.
        let rc = unsafe { MsiOpenDatabaseW(p.as_ptr(), MSIDBOPEN_CREATEDIRECT, &mut h) };
        let h = H(h);
        assert_eq!(rc, ERROR_SUCCESS, "create {}", path.display());
        Db(h)
    }

    fn view(&self, sql: &str) -> H {
        let q = wide(sql);
        let mut v: MsiHandle = 0;
        // SAFETY: open database, NUL-terminated query, valid out-pointer.
        let rc = unsafe { MsiDatabaseOpenViewW((self.0).0, q.as_ptr(), &mut v) };
        let v = H(v);
        assert_eq!(rc, ERROR_SUCCESS, "open view: {sql}");
        v
    }

    fn exec(&self, sql: &str) -> &Db {
        let v = self.view(sql);
        // SAFETY: open view, no parameters.
        assert_eq!(unsafe { MsiViewExecute(v.0, 0) }, ERROR_SUCCESS, "{sql}");
        self
    }

    fn insert(&self, table: &str, columns: &[&str], rows: &[&[V<'_>]]) -> &Db {
        let cols = columns
            .iter()
            .map(|c| format!("`{c}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let marks = vec!["?"; columns.len()].join(", ");
        let view = self.view(&format!("INSERT INTO `{table}` ({cols}) VALUES ({marks})"));
        // SAFETY: plain record allocation.
        let rec = H(unsafe { MsiCreateRecord(columns.len() as u32) });
        assert_ne!(rec.0, 0);
        for row in rows {
            assert_eq!(row.len(), columns.len());
            for (i, cell) in row.iter().enumerate() {
                let field = i as u32 + 1;
                // SAFETY: open record, field in range, NUL-terminated string.
                let rc = unsafe {
                    match *cell {
                        S(s) => MsiRecordSetStringW(rec.0, field, wide(s).as_ptr()),
                        I(n) => MsiRecordSetInteger(rec.0, field, n),
                    }
                };
                assert_eq!(rc, ERROR_SUCCESS);
            }
            // SAFETY: open view and record; closing the view allows the next execution.
            unsafe {
                assert_eq!(MsiViewExecute(view.0, rec.0), ERROR_SUCCESS, "{table}");
                MsiViewClose(view.0);
            }
        }
        self
    }

    fn finish(self) {
        // SAFETY: open database.
        assert_eq!(unsafe { MsiDatabaseCommit((self.0).0) }, ERROR_SUCCESS);
    }
}

const PROPERTY: &str = "CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` LONGCHAR NOT NULL LOCALIZABLE PRIMARY KEY `Property`)";
const COMPONENT: &str = "CREATE TABLE `Component` (`Component` CHAR(72) NOT NULL, `ComponentId` CHAR(38), `Directory_` CHAR(72) NOT NULL, `Attributes` SHORT NOT NULL, `Condition` CHAR(255), `KeyPath` CHAR(72) PRIMARY KEY `Component`)";
const REGISTRY: &str = "CREATE TABLE `Registry` (`Registry` CHAR(72) NOT NULL, `Root` SHORT NOT NULL, `Key` CHAR(255) NOT NULL LOCALIZABLE, `Name` CHAR(255) LOCALIZABLE, `Value` LONGCHAR LOCALIZABLE, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Registry`)";
const REMOVE_REGISTRY: &str = "CREATE TABLE `RemoveRegistry` (`RemoveRegistry` CHAR(72) NOT NULL, `Root` SHORT NOT NULL, `Key` CHAR(255) NOT NULL LOCALIZABLE, `Name` CHAR(255) LOCALIZABLE, `Component_` CHAR(72) NOT NULL PRIMARY KEY `RemoveRegistry`)";
const CLASS: &str = "CREATE TABLE `Class` (`CLSID` CHAR(38) NOT NULL, `Context` CHAR(32) NOT NULL, `Component_` CHAR(72) NOT NULL, `ProgId_Default` CHAR(255), `Description` CHAR(255) LOCALIZABLE, `AppId_` CHAR(38), `FileTypeMask` CHAR(255), `Icon_` CHAR(72), `IconIndex` SHORT, `DefInprocHandler` CHAR(32), `Argument` CHAR(255), `Feature_` CHAR(38) NOT NULL, `Attributes` SHORT PRIMARY KEY `CLSID`, `Context`, `Component_`)";
const PROGID: &str = "CREATE TABLE `ProgId` (`ProgId` CHAR(255) NOT NULL, `ProgId_Parent` CHAR(255), `Class_` CHAR(38), `Description` CHAR(255) LOCALIZABLE, `Icon_` CHAR(72), `IconIndex` SHORT PRIMARY KEY `ProgId`)";
const EXTENSION: &str = "CREATE TABLE `Extension` (`Extension` CHAR(255) NOT NULL, `Component_` CHAR(72) NOT NULL, `ProgId_` CHAR(255), `MIME_` CHAR(64), `Feature_` CHAR(38) NOT NULL PRIMARY KEY `Extension`, `Component_`)";
const TYPELIB: &str = "CREATE TABLE `TypeLib` (`LibID` CHAR(38) NOT NULL, `Language` SHORT NOT NULL, `Component_` CHAR(72) NOT NULL, `Version` LONG, `Description` CHAR(128) LOCALIZABLE, `Directory_` CHAR(72), `Feature_` CHAR(38) NOT NULL, `Cost` LONG PRIMARY KEY `LibID`, `Language`, `Component_`)";
const APPID: &str = "CREATE TABLE `AppId` (`AppId` CHAR(38) NOT NULL, `RemoteServerName` CHAR(255), `LocalService` CHAR(255), `ServiceParameters` CHAR(255), `DllSurrogate` CHAR(255), `ActivateAtStorage` SHORT, `RunAsInteractiveUser` SHORT PRIMARY KEY `AppId`)";
const SERVICE_INSTALL: &str = "CREATE TABLE `ServiceInstall` (`ServiceInstall` CHAR(72) NOT NULL, `Name` CHAR(255) NOT NULL, `DisplayName` CHAR(255) LOCALIZABLE, `ServiceType` LONG NOT NULL, `StartType` LONG NOT NULL, `ErrorControl` LONG NOT NULL, `LoadOrderGroup` CHAR(255), `Dependencies` CHAR(255), `StartName` CHAR(255), `Password` CHAR(255), `Arguments` CHAR(255), `Component_` CHAR(72) NOT NULL, `Description` CHAR(255) LOCALIZABLE PRIMARY KEY `ServiceInstall`)";
const CUSTOM_ACTION: &str = "CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(255), `ExtendedType` LONG PRIMARY KEY `Action`)";

const PRODUCT_CODE: &str = "{11111111-2222-3333-4444-555555555555}";
const CLSID: &str = "{BBBBBBBB-0000-0000-0000-000000000001}";
const APPID_GUID: &str = "{CCCCCCCC-0000-0000-0000-000000000001}";
const LIBID: &str = "{DDDDDDDD-0000-0000-0000-000000000001}";

/// A package with one row in every table the source reads (two in `Registry`), and `extra` more
/// `Registry` rows named `x<i>` (to tell packages apart in the parallel test).
fn build_msi(path: &Path, extra: usize) {
    let db = Db::create(path);
    for sql in [
        PROPERTY,
        COMPONENT,
        REGISTRY,
        REMOVE_REGISTRY,
        CLASS,
        PROGID,
        EXTENSION,
        TYPELIB,
        APPID,
        SERVICE_INSTALL,
        CUSTOM_ACTION,
    ] {
        db.exec(sql);
    }
    db.insert(
        "Property",
        &["Property", "Value"],
        &[
            &[S("ProductCode"), S(PRODUCT_CODE)],
            &[S("ProductName"), S("Test Product")],
            &[S("Manufacturer"), S("Test Maker")],
            &[S("VALNAME"), S("Setting")],
            &[S("UNREFERENCED"), S("x")],
        ],
    );
    db.insert(
        "Component",
        &[
            "Component",
            "ComponentId",
            "Directory_",
            "Attributes",
            "KeyPath",
        ],
        &[&[
            S("C1"),
            S("{AAAAAAAA-0000-0000-0000-000000000001}"),
            S("INSTALLDIR"),
            I(4),
            S("reg1"),
        ]],
    );
    let names: Vec<String> = (0..extra).map(|i| format!("x{i}")).collect();
    let mut rows: Vec<Vec<V<'_>>> = vec![
        vec![
            S("reg1"),
            I(2),
            S("Software\\[Manufacturer]\\[ProductName]"),
            S("[VALNAME]"),
            S("#1"),
            S("C1"),
        ],
        vec![
            S("reg2"),
            I(-1),
            S("Software\\Fixed"),
            S(""),
            S(""),
            S("C1"),
        ],
    ];
    for n in &names {
        rows.push(vec![S(n), I(1), S("Software\\Extra"), S(n), S(""), S("C1")]);
    }
    let rows: Vec<&[V<'_>]> = rows.iter().map(Vec::as_slice).collect();
    db.insert(
        "Registry",
        &["Registry", "Root", "Key", "Name", "Value", "Component_"],
        &rows,
    );
    db.insert(
        "RemoveRegistry",
        &["RemoveRegistry", "Root", "Key", "Name", "Component_"],
        &[&[S("rr1"), I(0), S("Test.Old"), S("-"), S("C1")]],
    );
    db.insert(
        "Class",
        &[
            "CLSID",
            "Context",
            "Component_",
            "ProgId_Default",
            "AppId_",
            "Feature_",
        ],
        &[&[
            S(CLSID),
            S("LocalServer32"),
            S("C1"),
            S("Test.Doc.1"),
            S(APPID_GUID),
            S("F1"),
        ]],
    );
    db.insert(
        "ProgId",
        &["ProgId", "Class_"],
        &[&[S("Test.Doc.1"), S(CLSID)]],
    );
    db.insert(
        "Extension",
        &["Extension", "Component_", "ProgId_", "Feature_"],
        &[&[S("tdoc"), S("C1"), S("Test.Doc.1"), S("F1")]],
    );
    db.insert(
        "TypeLib",
        &["LibID", "Language", "Component_", "Feature_"],
        &[&[S(LIBID), I(0), S("C1"), S("F1")]],
    );
    db.insert("AppId", &["AppId"], &[&[S(APPID_GUID)]]);
    db.insert(
        "ServiceInstall",
        &[
            "ServiceInstall",
            "Name",
            "ServiceType",
            "StartType",
            "ErrorControl",
            "Component_",
        ],
        &[&[S("svc1"), S("TestSvc"), I(16), I(3), I(1), S("C1")]],
    );
    db.insert(
        "CustomAction",
        &["Action", "Type"],
        &[&[S("CA1"), I(51)], &[S("CA2"), I(34)]],
    );
    db.finish();
}

/// What `msi_tables` returns for [`build_msi`]`(path, extra)`.
fn expected_tables(extra: usize) -> MsiTables {
    let mut registry = vec![
        MsiRegistryRaw {
            row: "reg1".into(),
            root: 2,
            key: "Software\\[Manufacturer]\\[ProductName]".into(),
            name: Some("[VALNAME]".into()),
            value: Some("#1".into()),
            component: "C1".into(),
        },
        MsiRegistryRaw {
            row: "reg2".into(),
            root: -1,
            key: "Software\\Fixed".into(),
            name: None,
            value: None,
            component: "C1".into(),
        },
    ];
    for i in 0..extra {
        registry.push(MsiRegistryRaw {
            row: format!("x{i}"),
            root: 1,
            key: "Software\\Extra".into(),
            name: Some(format!("x{i}")),
            value: None,
            component: "C1".into(),
        });
    }
    MsiTables {
        // The fixed properties the package has plus the ones Registry references; nothing else.
        properties: vec![
            ("ProductCode".into(), PRODUCT_CODE.into()),
            ("ProductName".into(), "Test Product".into()),
            ("Manufacturer".into(), "Test Maker".into()),
            ("VALNAME".into(), "Setting".into()),
        ],
        components: vec![MsiComponentRow {
            component: "C1".into(),
            component_id: Some("{AAAAAAAA-0000-0000-0000-000000000001}".into()),
            attributes: 4,
            key_path: Some("reg1".into()),
        }],
        registry,
        remove_registry: vec![MsiRegistryRaw {
            row: "rr1".into(),
            root: 0,
            key: "Test.Old".into(),
            name: Some("-".into()),
            value: None,
            component: "C1".into(),
        }],
        classes: vec![MsiClassRow {
            clsid: CLSID.into(),
            context: "LocalServer32".into(),
            component: "C1".into(),
            progid: Some("Test.Doc.1".into()),
            appid: Some(APPID_GUID.into()),
        }],
        progids: vec!["Test.Doc.1".into()],
        extensions: vec![MsiExtensionRow {
            extension: "tdoc".into(),
            component: "C1".into(),
            progid: Some("Test.Doc.1".into()),
        }],
        typelibs: vec![LIBID.into()],
        appids: vec![APPID_GUID.into()],
        service_install: vec![MsiServiceRaw {
            name: "TestSvc".into(),
            component: "C1".into(),
            service_type: 16,
            start_type: 3,
        }],
        custom_action_count: 2,
        truncated: false,
    }
}

/// The row order of a table without an explicit ORDER BY is the database's; compare sorted.
fn sorted(mut t: MsiTables) -> MsiTables {
    t.properties.sort();
    t.registry.sort_by(|a, b| a.row.cmp(&b.row));
    t
}

fn str_path(p: &Path) -> &str {
    p.to_str().unwrap()
}

// ---------------------------------------------------------------------------------------------------------
// Live MSI tables
// ---------------------------------------------------------------------------------------------------------

#[test]
fn live_msi_tables_of_generated_msi() {
    let dir = Scratch::new("tables");
    let path = dir.path("gen.msi");
    build_msi(&path, 0);
    let sys = LiveSystem::new();
    let got = sys.msi_tables(str_path(&path)).expect("msi_tables");
    assert_eq!(sorted(got), sorted(expected_tables(0)));

    // The read left no handle open: the file can be opened exclusively and removed.
    use std::os::windows::fs::OpenOptionsExt;
    let exclusive = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(&path);
    assert!(exclusive.is_ok(), "{:?}", exclusive.err());
    drop(exclusive);

    // A package with an empty database is readable and empty, never an error.
    let empty = dir.path("empty.msi");
    Db::create(&empty).finish();
    assert_eq!(sys.msi_tables(str_path(&empty)), Ok(MsiTables::default()));

    // A file that is not an MSI database is an error with a code, never an empty table set.
    let text = dir.path("text.msi");
    std::fs::write(&text, b"not a database").unwrap();
    match sys.msi_tables(str_path(&text)) {
        Err(SourceError::Other(code)) => assert_ne!(code, 0),
        other => panic!("not an MSI: {other:?}"),
    }
    // A relative path is refused before msi.dll sees it.
    assert_eq!(
        sys.msi_tables("gen.msi"),
        Err(SourceError::InvalidPath("gen.msi".into()))
    );
}

#[test]
fn live_msi_tables_missing_file_not_found() {
    let dir = Scratch::new("missing");
    let sys = LiveSystem::new();
    // A missing file in an existing directory, and a file in a missing directory.
    let missing = dir.path("gone.msi");
    assert_eq!(
        sys.msi_tables(str_path(&missing)),
        Err(SourceError::NotFound)
    );
    let deeper = dir.path("no-such-dir").join("gone.msi");
    assert_eq!(
        sys.msi_tables(str_path(&deeper)),
        Err(SourceError::NotFound)
    );
    // A directory where the package should be exists: not "not found".
    let as_dir = dir.path("dir.msi");
    std::fs::create_dir(&as_dir).unwrap();
    assert!(
        matches!(
            sys.msi_tables(str_path(&as_dir)),
            Err(SourceError::Other(_))
        ),
        "{:?}",
        sys.msi_tables(str_path(&as_dir))
    );
}

#[test]
fn live_msi_tables_parallel_calls() {
    let dir = Scratch::new("parallel");
    let a = dir.path("a.msi");
    let b = dir.path("b.msi");
    build_msi(&a, 0);
    build_msi(&b, 25);
    let missing = dir.path("gone.msi");
    let sys = LiveSystem::new();
    let (want_a, want_b) = (sorted(expected_tables(0)), sorted(expected_tables(25)));
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|t| {
                let (sys, a, b, missing) = (&sys, &a, &b, &missing);
                let (want_a, want_b) = (&want_a, &want_b);
                s.spawn(move || {
                    for i in 0..10 {
                        match (t + i) % 3 {
                            0 => assert_eq!(&sorted(sys.msi_tables(str_path(a)).unwrap()), want_a),
                            1 => assert_eq!(&sorted(sys.msi_tables(str_path(b)).unwrap()), want_b),
                            _ => assert_eq!(
                                sys.msi_tables(str_path(missing)),
                                Err(SourceError::NotFound)
                            ),
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("reader thread");
        }
    });
}

// ---------------------------------------------------------------------------------------------------------
// Live tasks
// ---------------------------------------------------------------------------------------------------------

const TASK_EXEC: &str = r"C:\PurgeTest\does-not-exist.exe";
const TASK_CLSID: &str = "{0F3C6D2A-5B1E-4C7D-9A8B-2E4F6A1C3D5E}";

/// A disabled, hidden task with no trigger that cannot be started on demand.
const TASK_XML: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>PurgeTest</Author><Description>purge-source m1b_live</Description></RegistrationInfo>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><Enabled>false</Enabled><AllowStartOnDemand>false</AllowStartOnDemand><Hidden>true</Hidden></Settings>
  <Actions Context="Author"><Exec><Command>C:\PurgeTest\does-not-exist.exe</Command><Arguments>--never</Arguments></Exec><ComHandler><ClassId>{0F3C6D2A-5B1E-4C7D-9A8B-2E4F6A1C3D5E}</ClassId></ComHandler></Actions>
</Task>"#;

/// Deletes the task on drop.
struct OwnTask(String);

impl Drop for OwnTask {
    fn drop(&mut self) {
        assert!(self.0.starts_with("\\PurgeTest-"));
        let ok = std::process::Command::new("schtasks.exe")
            .args(["/Delete", "/TN", &self.0, "/F"])
            .output()
            .is_ok_and(|o| o.status.success());
        if !ok {
            eprintln!("cleanup: could not delete task {}", self.0);
        }
    }
}

#[test]
fn live_tasks_lists_own_test_task() {
    let sys = LiveSystem::new();
    if !sys.elevated() {
        eprintln!(
            "skipped: live_tasks_lists_own_test_task registers a task and needs an elevated token"
        );
        return;
    }
    let dir = Scratch::new("task");
    let xml_path = dir.path("task.xml");
    let mut bytes = vec![0xFF, 0xFE];
    bytes.extend(TASK_XML.encode_utf16().flat_map(u16::to_le_bytes));
    std::fs::write(&xml_path, bytes).unwrap();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = format!("\\PurgeTest-{}-{nanos:x}", std::process::id());
    let out = std::process::Command::new("schtasks.exe")
        .args(["/Create", "/TN", &path, "/XML", str_path(&xml_path)])
        .output()
        .expect("run schtasks");
    let own = OwnTask(path.clone());
    assert!(
        out.status.success(),
        "schtasks /Create: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let tasks = sys.tasks().expect("tasks");
    let mine: Vec<&TaskInfo> = tasks.iter().filter(|t| t.identity.path == path).collect();
    assert_eq!(mine.len(), 1, "{path} listed once");
    let t = mine[0];
    assert_eq!(
        t.identity.actions,
        vec![
            TaskAction::Exec {
                path: TASK_EXEC.into(),
                arguments: Some("--never".into()),
                working_dir: None,
            },
            TaskAction::ComHandler {
                clsid: TASK_CLSID.into(),
                data: None,
            },
        ]
    );
    assert!(!t.enabled, "{t:?}");
    assert!(t.hidden, "hidden tasks are listed and flagged: {t:?}");
    assert!(!t.stored_password, "{t:?}");
    assert_eq!(t.author.as_deref(), Some("PurgeTest"));
    assert!(t.run_as.is_some(), "the registering user: {t:?}");
    // The system's own tasks are there too: the list is the whole tree, not one folder.
    assert!(
        tasks
            .iter()
            .any(|t| t.identity.path.starts_with("\\Microsoft\\Windows\\")),
        "no task under \\Microsoft\\Windows"
    );
    drop(own);
    let after = sys.tasks().expect("tasks after delete");
    assert!(!after.iter().any(|t| t.identity.path == path));
}

// ---------------------------------------------------------------------------------------------------------
// Snapshot fixture: tasks and MSI tables
// ---------------------------------------------------------------------------------------------------------

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn mini_snap() -> String {
    std::fs::read_to_string(fixtures_dir().join("mini.snap.tsv")).unwrap()
}

/// The mini lists with their `tasks` (and `errors`) sections replaced; `None` removes the section.
fn lists_with(tasks: Option<serde_json::Value>, errors: Option<serde_json::Value>) -> String {
    let text = std::fs::read_to_string(fixtures_dir().join("mini.lists.json")).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let obj = v.as_object_mut().unwrap();
    match tasks {
        Some(t) => obj.insert("tasks".into(), t),
        None => obj.remove("tasks"),
    };
    if let Some(e) = errors {
        obj.insert("errors".into(), e);
    }
    serde_json::to_string_pretty(&v).unwrap()
}

fn load(lists: &str) -> Result<Fixture, FixtureError> {
    Fixture::from_snap_parts(mini_snap().as_bytes(), Some(lists), None)
}

#[test]
fn snap_old_lists_not_captured() {
    use serde_json::json;
    // An M0/M1a/M2 lists document: tasks without the M1b fields.
    let old = lists_with(
        Some(json!([
            {"path": "\\Vendor\\Update", "actions": ["C:\\App\\u.exe /q"], "enabled": true},
            {"path": "\\Other", "actions": [], "enabled": false}
        ])),
        None,
    );
    let f = load(&old).unwrap();
    assert_eq!(f.tasks(), Err(SourceError::NotCaptured));
    assert_eq!(
        f.msi_tables(r"C:\Windows\Installer\1a2b3c.msi"),
        Err(SourceError::NotCaptured)
    );
    // Loads exactly as without any tasks section, and as the committed mini lists (empty section).
    let without = load(&lists_with(None, None)).unwrap();
    let committed =
        load(&std::fs::read_to_string(fixtures_dir().join("mini.lists.json")).unwrap()).unwrap();
    assert_eq!(f.to_json(), without.to_json());
    assert_eq!(f.to_json(), committed.to_json());
    assert_eq!(committed.tasks(), Err(SourceError::NotCaptured));

    // A failed tasks section (the rig then writes an empty one) is unknown, never "no tasks".
    let failed = lists_with(Some(json!([])), Some(json!(["tasks: Access is denied."])));
    assert_eq!(
        load(&failed).unwrap().tasks(),
        Err(SourceError::NotCaptured)
    );
    // An M1b entry does not help when the section is reported as failed.
    let failed_m1b = lists_with(
        Some(json!([{"path": "\\T", "enabled": true, "actions_detail": []}])),
        Some(json!(["tasks: timeout"])),
    );
    assert_eq!(
        load(&failed_m1b).unwrap().tasks(),
        Err(SourceError::NotCaptured)
    );

    // A snapshot on disk with no tables file beside it: MSI tables not captured.
    let dir = Scratch::new("oldsnap");
    let snap = dir.path("snap-mini-1.tsv");
    std::fs::write(&snap, mini_snap()).unwrap();
    let lists = dir.path("lists-mini-1.json");
    std::fs::write(&lists, &old).unwrap();
    let f = Fixture::from_snap(&snap, Some(&lists), None).unwrap();
    assert_eq!(f.tasks(), Err(SourceError::NotCaptured));
    assert_eq!(
        f.msi_tables(r"C:\Windows\Installer\1a2b3c.msi"),
        Err(SourceError::NotCaptured)
    );
    assert_eq!(f.to_json(), without.to_json());
}

#[test]
fn snap_new_lists_tasks_loaded() {
    use serde_json::json;
    let new = lists_with(
        Some(json!([
            {
                "path": "\\PurgeTrap\\A Update", "actions": ["C:\\A\\a.exe /x", "com:{11111111-2222-3333-4444-555555555555} d"],
                "enabled": true, "hidden": true, "logon_type": "Interactive", "has_stored_password": false,
                "actions_detail": [
                    {"kind": "exec", "path": "C:\\A\\a.exe", "arguments": "/x", "working_dir": "", "clsid": null, "data": null},
                    {"kind": "com_handler", "path": null, "arguments": null, "working_dir": null,
                     "clsid": "{11111111-2222-3333-4444-555555555555}", "data": "d"}
                ]
            },
            {
                // PowerShell wrote the one-element list as the element itself.
                "path": "\\B", "actions": ["MSFT_TaskSendEmailAction"], "enabled": false, "hidden": false,
                "logon_type": "Password", "has_stored_password": true,
                "actions_detail": {"kind": "other", "path": null, "arguments": null, "working_dir": null,
                                   "clsid": null, "data": "MSFT_TaskSendEmailAction"}
            },
            {
                "path": "\\C", "actions": [], "enabled": true, "hidden": false, "logon_type": null,
                "has_stored_password": false, "actions_detail": []
            },
            {
                "path": "\\D", "actions": [], "enabled": true, "hidden": false, "logon_type": "S4U",
                "has_stored_password": false,
                "actions_detail": [{"kind": "other", "data": "MSFT_TaskShowMessageAction"},
                                   {"kind": "other", "data": "MSFT_TaskSomethingNew"}]
            }
        ])),
        None,
    );
    let f = load(&new).unwrap();
    let tasks = f.tasks().unwrap();
    assert_eq!(tasks.len(), 4);

    let a = &tasks[0];
    assert_eq!(a.identity.path, "\\PurgeTrap\\A Update");
    assert_eq!(
        a.identity.actions,
        vec![
            TaskAction::Exec {
                path: "C:\\A\\a.exe".into(),
                arguments: Some("/x".into()),
                // Empty is stored as nothing, as the live source reads it.
                working_dir: None,
            },
            TaskAction::ComHandler {
                clsid: "{11111111-2222-3333-4444-555555555555}".into(),
                data: Some("d".into()),
            },
        ]
    );
    assert!(a.enabled && a.hidden && !a.stored_password);
    // Not captured by the rig.
    assert_eq!((a.author.as_deref(), a.run_as.as_deref()), (None, None));

    let b = &tasks[1];
    assert_eq!(
        b.identity.actions,
        vec![TaskAction::Other {
            kind: "send_email".into()
        }]
    );
    assert!(!b.enabled && b.stored_password);

    // No logon type: the cautious answer; no actions: kept, with the actions unknown.
    let c = &tasks[2];
    assert!(c.identity.actions.is_empty());
    assert!(c.stored_password);

    let d = &tasks[3];
    assert_eq!(
        d.identity.actions,
        vec![
            TaskAction::Other {
                kind: "show_message".into()
            },
            TaskAction::Other {
                kind: "MSFT_TaskSomethingNew".into()
            },
        ]
    );
    assert!(!d.stored_password);

    // The digest of a snapshot task equals the digest of the same task read live.
    let live_form = purge_model::object::TaskIdentity {
        path: "\\PurgeTrap\\A Update".into(),
        actions: a.identity.actions.clone(),
    };
    assert_eq!(a.identity.fp(), live_form.fp());

    // Refused: only some entries with the M1b fields, an unknown action kind, a path without the
    // leading backslash, a flag that is not a boolean.
    for bad in [
        json!([
            {"path": "\\A", "enabled": true, "actions_detail": []},
            {"path": "\\B", "actions": [], "enabled": true}
        ]),
        json!([{"path": "\\A", "enabled": true, "actions_detail": [{"kind": "run"}]}]),
        json!([{"path": "A", "enabled": true, "actions_detail": []}]),
        json!([{"path": "\\A", "enabled": "yes", "actions_detail": []}]),
        json!([{"path": "\\A", "enabled": true, "actions_detail": [{"kind": "exec", "path": 3}]}]),
    ] {
        let doc = lists_with(Some(bad.clone()), None);
        assert!(
            matches!(load(&doc), Err(FixtureError::Invalid(_))),
            "{bad}: {:?}",
            load(&doc).map(|f| f.tasks())
        );
    }
}

/// An MSI tables document for the mini snapshot.
fn tables_doc(packages: serde_json::Value) -> String {
    serde_json::json!({"schema": "purge.rig.msi_tables/1", "packages": packages}).to_string()
}

#[test]
fn snap_msi_tables_file_loaded() {
    use serde_json::json;
    let pkg = r"C:\Windows\Installer\1a2b3c.msi";
    let lists = std::fs::read_to_string(fixtures_dir().join("mini.lists.json")).unwrap();

    // The file name follows the snapshot's.
    assert_eq!(
        msi_tables_file_for(Path::new(r"C:\r\snap-7zip-2.tsv.gz")),
        Some(PathBuf::from(r"C:\r\msi-tables-7zip-2.json"))
    );
    assert_eq!(
        msi_tables_file_for(Path::new(r"C:\r\snap-7zip-2.tsv")),
        Some(PathBuf::from(r"C:\r\msi-tables-7zip-2.json"))
    );
    assert_eq!(msi_tables_file_for(Path::new(r"C:\r\other.tsv.gz")), None);

    let long = "k".repeat(MAX_CELL_BYTES + 1);
    let doc = tables_doc(json!({
        pkg: {
            "properties": [["ProductCode", PRODUCT_CODE]],
            "registry": [
                {"row": "r1", "root": 2, "key": "Software\\Vendor", "name": null, "value": null, "component": "C1"},
                {"row": "r2", "root": 2, "key": long, "component": "C1"}
            ],
            "custom_action_count": 3
        },
        r"C:\Windows\Installer\unreadable.msi": {"truncated": true}
    }));

    for gz in [false, true] {
        let dir = Scratch::new(if gz { "tables-gz" } else { "tables" });
        let snap = dir.path("snap-mini-1.tsv");
        std::fs::write(&snap, mini_snap()).unwrap();
        let lists_path = dir.path("lists-mini-1.json");
        std::fs::write(&lists_path, &lists).unwrap();
        let tables_path = msi_tables_file_for(&snap).unwrap();
        if gz {
            use std::io::Write;
            let mut enc = flate2::write::GzEncoder::new(
                std::fs::File::create(&tables_path).unwrap(),
                flate2::Compression::default(),
            );
            enc.write_all(doc.as_bytes()).unwrap();
            enc.finish().unwrap();
        } else {
            std::fs::write(&tables_path, &doc).unwrap();
        }
        let f = Fixture::from_snap(&snap, Some(&lists_path), None).unwrap();

        // Any case and slash form of the path.
        for spelling in [
            pkg,
            r"c:\windows\installer\1A2B3C.MSI",
            "C:/Windows/Installer/1a2b3c.msi",
        ] {
            let t = f.msi_tables(spelling).unwrap();
            assert_eq!(
                t.properties,
                vec![("ProductCode".to_string(), PRODUCT_CODE.to_string())]
            );
            // The row with the over-long cell is dropped and counted.
            assert_eq!(t.registry.len(), 1, "{spelling}");
            assert_eq!(t.registry[0].row, "r1");
            assert!(t.truncated);
            assert_eq!(t.custom_action_count, 3);
        }
        assert!(
            f.msi_tables(r"C:\Windows\Installer\unreadable.msi")
                .unwrap()
                .truncated
        );
        // A package the file does not list: not found.
        assert_eq!(
            f.msi_tables(r"C:\Windows\Installer\other.msi"),
            Err(SourceError::NotFound)
        );
        // The rest of the snapshot is as without the file; the old lists still give no tasks.
        assert_eq!(f.tasks(), Err(SourceError::NotCaptured));
        assert_eq!(f.snap_stats().unwrap().keys, 7);
    }

    // Refused documents: wrong schema, unknown fields (top level, tables, rows), a package listed twice,
    // a relative package path. A refused document changes nothing.
    let mut base = load(&lists).unwrap();
    let refused = [
        json!({"schema": "purge.rig.msi_tables/2", "packages": {}}).to_string(),
        json!({"schema": "purge.rig.msi_tables/1", "packages": {}, "extra": 1}).to_string(),
        json!({"schema": "purge.rig.msi_tables/1"}).to_string(),
        tables_doc(json!({pkg: {"propertys": []}})),
        tables_doc(
            json!({pkg: {"registry": [{"row": "r", "root": 2, "key": "k", "component": "c", "colour": 1}]}}),
        ),
        format!(
            r#"{{"schema":"purge.rig.msi_tables/1","packages":{{"{0}":{{}},"{0}":{{}}}}}}"#,
            pkg.replace('\\', "\\\\")
        ),
        tables_doc(json!({pkg: {}, r"c:/windows/installer/1A2B3C.msi": {}})),
        tables_doc(json!({"1a2b3c.msi": {}})),
    ];
    for doc in &refused {
        assert!(base.apply_msi_tables_json(doc).is_err(), "{doc}");
        assert_eq!(base.msi_tables(pkg), Err(SourceError::NotCaptured), "{doc}");
    }
    // An empty package map is a captured "nothing": every package is not found.
    base.apply_msi_tables_json(&tables_doc(json!({}))).unwrap();
    assert_eq!(base.msi_tables(pkg), Err(SourceError::NotFound));
}
