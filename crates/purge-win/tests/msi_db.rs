//! MSI database wrapper tests.
//!
//! Every database is built by the test itself with `MsiOpenDatabaseW(CREATEDIRECT)` and SQL (and, for
//! the 200,001-row table, an IDT import), in a fresh
//! directory under `%TEMP%` that is removed when the test ends (pass or fail). The one host test reads
//! installed products' cached packages read-only.

use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use purge_win::msi_db::{
    ClassRow, ComponentRow, ExtensionRow, RawTables, RegistryRow, ServiceInstallRow, TableLimits,
    WinError, read_tables,
};
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::ApplicationInstallationAndServicing::{
    MSIDBOPEN_CREATEDIRECT, MSIHANDLE, MsiCloseHandle, MsiCreateRecord, MsiDatabaseCommit,
    MsiDatabaseImportW, MsiDatabaseOpenViewW, MsiOpenDatabaseW, MsiRecordSetInteger,
    MsiRecordSetStringW, MsiViewClose, MsiViewExecute,
};

// ---------------------------------------------------------------------------------------------
// Scratch directory and database builder
// ---------------------------------------------------------------------------------------------

/// A unique directory under `std::env::temp_dir()`, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "purge-win-msidb-{tag}-{}-{nanos}",
            std::process::id()
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

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn path_wide(p: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

struct H(MSIHANDLE);

impl Drop for H {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: handle owned by this guard.
            unsafe { MsiCloseHandle(self.0) };
        }
    }
}

/// A cell value for an insert.
#[derive(Clone, Copy)]
enum V<'a> {
    S(&'a str),
    I(i32),
    Null,
}
use V::{I, Null, S};

/// A database under construction. `finish` commits and closes it.
struct Db(H);

impl Db {
    fn create(path: &Path) -> Db {
        let p = path_wide(path);
        let mut h: MSIHANDLE = 0;
        // SAFETY: NUL-terminated path, predefined persist mode, valid out-pointer.
        let rc = unsafe { MsiOpenDatabaseW(p.as_ptr(), MSIDBOPEN_CREATEDIRECT, &mut h) };
        let h = H(h);
        assert_eq!(rc, ERROR_SUCCESS, "create {}", path.display());
        Db(h)
    }

    fn view(&self, sql: &str) -> H {
        let q = wide(sql);
        let mut v: MSIHANDLE = 0;
        // SAFETY: open database, NUL-terminated query, valid out-pointer.
        let rc = unsafe { MsiDatabaseOpenViewW((self.0).0, q.as_ptr(), &mut v) };
        let v = H(v);
        assert_eq!(rc, ERROR_SUCCESS, "open view: {sql}");
        v
    }

    fn exec(&self, sql: &str) -> &Db {
        let v = self.view(sql);
        // SAFETY: open view, no parameters.
        let rc = unsafe { MsiViewExecute(v.0, 0) };
        assert_eq!(rc, ERROR_SUCCESS, "execute: {sql}");
        self
    }

    /// Inserts rows through one prepared `INSERT ... VALUES (?, ...)` view.
    fn insert<'a>(
        &self,
        table: &str,
        columns: &[&str],
        rows: impl IntoIterator<Item = Vec<V<'a>>>,
    ) -> &Db {
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
                // SAFETY: open record, field in range, NUL-terminated strings.
                let rc = unsafe {
                    match *cell {
                        S(s) => MsiRecordSetStringW(rec.0, field, wide(s).as_ptr()),
                        I(n) => MsiRecordSetInteger(rec.0, field, n),
                        Null => MsiRecordSetStringW(rec.0, field, wide("").as_ptr()),
                    }
                };
                assert_eq!(rc, ERROR_SUCCESS);
            }
            // SAFETY: open view and record.
            let rc = unsafe { MsiViewExecute(view.0, rec.0) };
            assert_eq!(rc, ERROR_SUCCESS, "insert into {table}");
            // SAFETY: open view; closing allows the next execution.
            unsafe { MsiViewClose(view.0) };
        }
        self
    }

    /// Bulk-loads a table from an IDT text file written in `folder` (row-by-row inserts of 200,000
    /// rows take minutes; an import takes seconds). The file is left for the scratch directory to
    /// remove.
    fn import_idt(&self, folder: &Path, file: &str, text: &str) -> &Db {
        std::fs::write(folder.join(file), text).unwrap();
        let (f, n) = (path_wide(folder), wide(file));
        // SAFETY: open database, NUL-terminated folder and file names.
        let rc = unsafe { MsiDatabaseImportW((self.0).0, f.as_ptr(), n.as_ptr()) };
        assert_eq!(rc, ERROR_SUCCESS, "import {file}");
        self
    }

    fn finish(self) {
        // SAFETY: open database.
        let rc = unsafe { MsiDatabaseCommit((self.0).0) };
        assert_eq!(rc, ERROR_SUCCESS, "commit");
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

const REGISTRY_COLS: [&str; 6] = ["Registry", "Root", "Key", "Name", "Value", "Component_"];

fn read(path: &Path) -> RawTables {
    read_tables(path, &TableLimits::default()).expect("read_tables")
}

/// Opens the file with no sharing at all: succeeds only when no handle to it is left open.
fn assert_no_open_handle(path: &Path) {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(path);
    assert!(
        f.is_ok(),
        "exclusive open of {} failed: {:?}",
        path.display(),
        f.err()
    );
}

fn reg(row: &str, root: i32, key: &str, name: Option<&str>, value: Option<&str>) -> RegistryRow {
    RegistryRow {
        row: row.into(),
        root,
        key: key.into(),
        name: name.map(Into::into),
        value: value.map(Into::into),
        component: "C1".into(),
    }
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[test]
fn reads_tables_of_generated_msi() {
    let dir = Scratch::new("full");
    let path = dir.path("full.msi");
    let db = Db::create(&path);
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
        [
            vec![
                S("ProductCode"),
                S("{11111111-2222-3333-4444-555555555555}"),
            ],
            vec![
                S("UpgradeCode"),
                S("{66666666-7777-8888-9999-AAAAAAAAAAAA}"),
            ],
            vec![S("ProductName"), S("Test Product")],
            vec![S("ProductVersion"), S("1.2.3")],
            vec![S("Manufacturer"), S("Test Maker")],
            vec![S("ALLUSERS"), S("1")],
            vec![S("ARPINSTALLLOCATION"), S("C:\\Test")],
            vec![S("COMPANYDIR"), S("Maker Inc")],
            vec![S("VALNAME"), S("Setting")],
            vec![S("REMOVEDKEY"), S("Old")],
            vec![S("UNREFERENCED"), S("x")],
            vec![S("SecureCustomProperties"), S("A;B")],
        ],
    );
    db.insert(
        "Component",
        &[
            "Component",
            "ComponentId",
            "Directory_",
            "Attributes",
            "Condition",
            "KeyPath",
        ],
        [
            vec![
                S("C1"),
                S("{AAAAAAAA-0000-0000-0000-000000000001}"),
                S("INSTALLDIR"),
                I(0),
                Null,
                S("app.exe"),
            ],
            vec![
                S("C2"),
                S("{AAAAAAAA-0000-0000-0000-000000000002}"),
                S("INSTALLDIR"),
                I(4),
                S("VersionNT64"),
                S("reg1"),
            ],
        ],
    );
    db.insert(
        "Registry",
        &REGISTRY_COLS,
        [
            vec![
                S("reg1"),
                I(2),
                S("Software\\[COMPANYDIR]\\[ProductName]"),
                S("[VALNAME]"),
                S("#1"),
                S("C1"),
            ],
            vec![S("reg2"), I(-1), S("Software\\Fixed"), Null, Null, S("C1")],
        ],
    );
    db.insert(
        "RemoveRegistry",
        &["RemoveRegistry", "Root", "Key", "Name", "Component_"],
        [vec![
            S("rr1"),
            I(1),
            S("Software\\[REMOVEDKEY]"),
            S("-"),
            S("C1"),
        ]],
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
        [vec![
            S("{BBBBBBBB-0000-0000-0000-000000000001}"),
            S("LocalServer32"),
            S("C1"),
            S("Test.Doc.1"),
            S("{CCCCCCCC-0000-0000-0000-000000000001}"),
            S("F1"),
        ]],
    );
    db.insert(
        "ProgId",
        &["ProgId", "Class_"],
        [
            vec![S("Test.Doc.1"), S("{BBBBBBBB-0000-0000-0000-000000000001}")],
            vec![S("Test.Doc"), Null],
        ],
    );
    db.insert(
        "Extension",
        &["Extension", "Component_", "ProgId_", "Feature_"],
        [vec![S("tdoc"), S("C1"), S("Test.Doc.1"), S("F1")]],
    );
    db.insert(
        "TypeLib",
        &["LibID", "Language", "Component_", "Feature_"],
        [vec![
            S("{DDDDDDDD-0000-0000-0000-000000000001}"),
            I(0),
            S("C1"),
            S("F1"),
        ]],
    );
    db.insert(
        "AppId",
        &["AppId"],
        [vec![S("{CCCCCCCC-0000-0000-0000-000000000001}")]],
    );
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
        [vec![S("svc1"), S("TestSvc"), I(16), I(2), I(1), S("C1")]],
    );
    db.insert(
        "CustomAction",
        &["Action", "Type"],
        [
            vec![S("CA1"), I(51)],
            vec![S("CA2"), I(34)],
            vec![S("CA3"), I(1)],
        ],
    );
    db.finish();

    let t = read(&path);
    assert!(!t.truncated);
    let props: Vec<(&str, &str)> = t
        .properties
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    assert_eq!(
        props,
        [
            ("ProductCode", "{11111111-2222-3333-4444-555555555555}"),
            ("UpgradeCode", "{66666666-7777-8888-9999-AAAAAAAAAAAA}"),
            ("ProductName", "Test Product"),
            ("ProductVersion", "1.2.3"),
            ("Manufacturer", "Test Maker"),
            ("ALLUSERS", "1"),
            ("ARPINSTALLLOCATION", "C:\\Test"),
            ("COMPANYDIR", "Maker Inc"),
            ("VALNAME", "Setting"),
            ("REMOVEDKEY", "Old"),
        ],
        "fixed properties plus the ones Registry/RemoveRegistry reference, nothing else"
    );
    assert_eq!(
        t.components,
        [
            ComponentRow {
                component: "C1".into(),
                component_id: Some("{AAAAAAAA-0000-0000-0000-000000000001}".into()),
                attributes: 0,
                key_path: Some("app.exe".into()),
            },
            ComponentRow {
                component: "C2".into(),
                component_id: Some("{AAAAAAAA-0000-0000-0000-000000000002}".into()),
                attributes: 4,
                key_path: Some("reg1".into()),
            },
        ]
    );
    assert_eq!(
        t.registry,
        [
            reg(
                "reg1",
                2,
                "Software\\[COMPANYDIR]\\[ProductName]",
                Some("[VALNAME]"),
                Some("#1")
            ),
            reg("reg2", -1, "Software\\Fixed", None, None),
        ]
    );
    assert_eq!(
        t.remove_registry,
        [reg("rr1", 1, "Software\\[REMOVEDKEY]", Some("-"), None)]
    );
    assert_eq!(
        t.classes,
        [ClassRow {
            clsid: "{BBBBBBBB-0000-0000-0000-000000000001}".into(),
            context: "LocalServer32".into(),
            component: "C1".into(),
            progid: Some("Test.Doc.1".into()),
            appid: Some("{CCCCCCCC-0000-0000-0000-000000000001}".into()),
        }]
    );
    let mut progids = t.progids.clone();
    progids.sort();
    assert_eq!(progids, ["Test.Doc", "Test.Doc.1"]);
    assert_eq!(
        t.extensions,
        [ExtensionRow {
            extension: "tdoc".into(),
            component: "C1".into(),
            progid: Some("Test.Doc.1".into()),
        }]
    );
    assert_eq!(t.typelibs, ["{DDDDDDDD-0000-0000-0000-000000000001}"]);
    assert_eq!(t.appids, ["{CCCCCCCC-0000-0000-0000-000000000001}"]);
    assert_eq!(
        t.service_install,
        [ServiceInstallRow {
            name: "TestSvc".into(),
            component: "C1".into(),
            service_type: 16,
            start_type: 2,
        }]
    );
    assert_eq!(t.custom_action_count, 3);
    assert_no_open_handle(&path);
}

#[test]
fn missing_table_is_empty_not_error() {
    let dir = Scratch::new("missing");
    let path = dir.path("only-property.msi");
    let db = Db::create(&path);
    db.exec(PROPERTY);
    db.insert(
        "Property",
        &["Property", "Value"],
        [vec![
            S("ProductCode"),
            S("{11111111-2222-3333-4444-555555555555}"),
        ]],
    );
    db.finish();
    let t = read(&path);
    assert_eq!(
        t,
        RawTables {
            properties: vec![(
                "ProductCode".into(),
                "{11111111-2222-3333-4444-555555555555}".into()
            )],
            ..RawTables::default()
        }
    );

    // A database with no tables at all is also readable and empty.
    let empty = dir.path("empty.msi");
    Db::create(&empty).finish();
    assert_eq!(read(&empty), RawTables::default());
}

#[test]
fn not_an_msi_is_error() {
    let dir = Scratch::new("notmsi");
    let text = dir.path("text.msi");
    std::fs::write(&text, b"this is not a compound file, just text\r\n").unwrap();
    let zero = dir.path("zero.msi");
    std::fs::write(&zero, b"").unwrap();
    // A compound-file signature followed by garbage.
    let fake = dir.path("fake.msi");
    let mut bytes = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    bytes.extend(std::iter::repeat_n(0xFFu8, 4096));
    std::fs::write(&fake, &bytes).unwrap();
    let missing = dir.path("does-not-exist.msi");
    for p in [&text, &zero, &fake, &missing, &dir.0] {
        let r = read_tables(p, &TableLimits::default());
        assert!(
            matches!(r, Err(WinError::Open(_))),
            "{}: {r:?}",
            p.display()
        );
    }
    for p in [&text, &zero, &fake] {
        assert_no_open_handle(p);
    }
}

#[test]
fn relative_path_rejected() {
    // Even when a file of that name exists in the current directory, it is not looked up.
    for p in [
        "relative.msi",
        r"sub\x.msi",
        r"C:relative.msi",
        r"\rooted.msi",
        r"\\.\pipe\x",
    ] {
        let r = read_tables(Path::new(p), &TableLimits::default());
        assert!(matches!(r, Err(WinError::InvalidPath(_))), "{p}: {r:?}");
    }
}

#[test]
fn row_limit_sets_truncated() {
    // Hostile: one row more than the contract's limit.
    let dir = Scratch::new("rows");
    let path = dir.path("rows.msi");
    let db = Db::create(&path);
    let started = Instant::now();
    let mut idt = String::from(
        "Registry\tRoot\tKey\tName\tValue\tComponent_\r\n\
         s72\ti2\tl255\tL255\tL0\ts72\r\n\
         Registry\tRegistry\r\n",
    );
    for i in 0..200_001 {
        idt.push_str(&format!("r{i}\t2\tSoftware\\T\tn{i}\t\tC1\r\n"));
    }
    db.import_idt(&dir.0, "Registry.idt", &idt);
    db.finish();
    println!("built 200,001-row table in {:?}", started.elapsed());
    let started = Instant::now();
    let t = read(&path);
    println!("read it in {:?}", started.elapsed());
    assert!(t.truncated);
    assert_eq!(t.registry.len(), 200_000);
    assert_no_open_handle(&path);

    // The boundary, with small limits: exactly max_rows is complete, one more is truncated.
    for (rows, truncated) in [(3usize, false), (4, true)] {
        let path = dir.path(&format!("small-{rows}.msi"));
        let db = Db::create(&path);
        db.exec(REGISTRY).exec(CUSTOM_ACTION);
        let names: Vec<String> = (0..rows).map(|i| format!("r{i}")).collect();
        db.insert(
            "Registry",
            &REGISTRY_COLS,
            names
                .iter()
                .map(|n| vec![S(n), I(2), S("K"), Null, Null, S("C1")]),
        );
        db.insert(
            "CustomAction",
            &["Action", "Type"],
            names.iter().map(|n| vec![S(n), I(1)]),
        );
        db.finish();
        let limits = TableLimits {
            max_rows: 3,
            ..TableLimits::default()
        };
        let t = read_tables(&path, &limits).unwrap();
        assert_eq!(t.truncated, truncated, "{rows} rows");
        assert_eq!(t.registry.len(), 3);
        assert_eq!(t.custom_action_count, 3);
    }
}

#[test]
fn cell_limit_sets_truncated() {
    let dir = Scratch::new("cells");
    let at_limit = "v".repeat(65_536);
    let over_limit = "w".repeat(65_537);

    let ok = dir.path("at-limit.msi");
    let db = Db::create(&ok);
    db.exec(REGISTRY);
    db.insert(
        "Registry",
        &REGISTRY_COLS,
        [vec![S("r1"), I(2), S("K"), S("N"), S(&at_limit), S("C1")]],
    );
    db.finish();
    let t = read(&ok);
    assert!(!t.truncated);
    assert_eq!(t.registry.len(), 1);
    assert_eq!(t.registry[0].value.as_deref(), Some(at_limit.as_str()));

    // Hostile: one unit over the limit. The row is dropped whole, the other row is kept.
    let over = dir.path("over-limit.msi");
    let db = Db::create(&over);
    db.exec(REGISTRY);
    db.insert(
        "Registry",
        &REGISTRY_COLS,
        [
            vec![S("r1"), I(2), S("K"), S("N"), S(&over_limit), S("C1")],
            vec![S("r2"), I(2), S("K"), S("M"), S("small"), S("C1")],
        ],
    );
    db.finish();
    let t = read(&over);
    assert!(t.truncated);
    assert_eq!(t.registry, [reg("r2", 2, "K", Some("M"), Some("small"))]);

    // Small limit: a key column over the limit drops the row too.
    let limits = TableLimits {
        max_cell: 4,
        ..TableLimits::default()
    };
    let t = read_tables(&over, &limits).unwrap();
    assert!(t.truncated);
    assert!(t.registry.is_empty(), "{:?}", t.registry);
    assert_no_open_handle(&over);
}

#[test]
fn handles_closed() {
    let dir = Scratch::new("handles");
    // Success path.
    let good = dir.path("good.msi");
    let db = Db::create(&good);
    db.exec(PROPERTY).exec(REGISTRY);
    db.insert(
        "Property",
        &["Property", "Value"],
        [vec![S("ProductName"), S("P")]],
    );
    db.insert(
        "Registry",
        &REGISTRY_COLS,
        [vec![S("r1"), I(2), S("K"), S("N"), S("V"), S("C1")]],
    );
    db.finish();
    for _ in 0..3 {
        read(&good);
        assert_no_open_handle(&good);
    }

    // Error path in the middle of reading: a Registry table without the Value column.
    let bad = dir.path("bad-table.msi");
    let db = Db::create(&bad);
    db.exec(PROPERTY).exec(
        "CREATE TABLE `Registry` (`Registry` CHAR(72) NOT NULL, `Root` SHORT NOT NULL, `Key` CHAR(255) NOT NULL, `Name` CHAR(255), `Component_` CHAR(72) NOT NULL PRIMARY KEY `Registry`)",
    );
    db.insert(
        "Registry",
        &["Registry", "Root", "Key", "Name", "Component_"],
        [vec![S("r1"), I(2), S("K"), S("N"), S("C1")]],
    );
    db.finish();
    let r = read_tables(&bad, &TableLimits::default());
    assert!(
        matches!(
            r,
            Err(WinError::Table {
                table: "Registry",
                ..
            })
        ),
        "a malformed table must fail the whole package: {r:?}"
    );
    assert_no_open_handle(&bad);

    // Error path at open.
    let text = dir.path("text.msi");
    std::fs::write(&text, b"not an msi").unwrap();
    assert!(read_tables(&text, &TableLimits::default()).is_err());
    assert_no_open_handle(&text);
}

#[test]
fn null_cells_are_none() {
    let dir = Scratch::new("nulls");
    let path = dir.path("nulls.msi");
    let db = Db::create(&path);
    db.exec(COMPONENT)
        .exec(REGISTRY)
        .exec(CLASS)
        .exec(EXTENSION)
        .exec(PROPERTY);
    db.insert(
        "Component",
        &[
            "Component",
            "ComponentId",
            "Directory_",
            "Attributes",
            "KeyPath",
        ],
        [vec![S("C1"), Null, S("D"), I(0), Null]],
    );
    db.insert(
        "Registry",
        &REGISTRY_COLS,
        [vec![S("r1"), I(2), S("K"), Null, Null, S("C1")]],
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
        [vec![
            S("{BBBBBBBB-0000-0000-0000-000000000001}"),
            S("InprocServer32"),
            S("C1"),
            Null,
            Null,
            S("F1"),
        ]],
    );
    db.insert(
        "Extension",
        &["Extension", "Component_", "ProgId_", "Feature_"],
        [vec![S("ext"), S("C1"), Null, S("F1")]],
    );
    db.finish();
    let t = read(&path);
    assert!(!t.truncated);
    assert_eq!(
        t.components,
        [ComponentRow {
            component: "C1".into(),
            component_id: None,
            attributes: 0,
            key_path: None,
        }]
    );
    assert_eq!(t.registry, [reg("r1", 2, "K", None, None)]);
    assert_eq!(t.classes.len(), 1);
    assert_eq!(t.classes[0].progid, None);
    assert_eq!(t.classes[0].appid, None);
    assert_eq!(
        t.extensions,
        [ExtensionRow {
            extension: "ext".into(),
            component: "C1".into(),
            progid: None,
        }]
    );
}

#[test]
fn registry_name_plus_minus_star_preserved() {
    let dir = Scratch::new("markers");
    let path = dir.path("markers.msi");
    let db = Db::create(&path);
    db.exec(REGISTRY).exec(REMOVE_REGISTRY);
    db.insert(
        "Registry",
        &REGISTRY_COLS,
        [
            vec![S("plus"), I(2), S("Software\\A"), S("+"), Null, S("C1")],
            vec![S("minus"), I(2), S("Software\\B"), S("-"), Null, S("C1")],
            vec![S("star"), I(2), S("Software\\C"), S("*"), Null, S("C1")],
            vec![S("named"), I(2), S("Software\\D"), S("+x"), S("1"), S("C1")],
        ],
    );
    db.insert(
        "RemoveRegistry",
        &["RemoveRegistry", "Root", "Key", "Name", "Component_"],
        [
            vec![S("rminus"), I(3), S("Software\\E"), S("-"), S("C1")],
            vec![S("rstar"), I(0), S("Software\\F"), S("*"), S("C1")],
        ],
    );
    db.finish();
    let t = read(&path);
    let mut registry = t.registry.clone();
    registry.sort_by(|a, b| a.row.cmp(&b.row));
    assert_eq!(
        registry,
        [
            reg("minus", 2, "Software\\B", Some("-"), None),
            reg("named", 2, "Software\\D", Some("+x"), Some("1")),
            reg("plus", 2, "Software\\A", Some("+"), None),
            reg("star", 2, "Software\\C", Some("*"), None),
        ]
    );
    let mut remove = t.remove_registry.clone();
    remove.sort_by(|a, b| a.row.cmp(&b.row));
    assert_eq!(
        remove,
        [
            reg("rminus", 3, "Software\\E", Some("-"), None),
            reg("rstar", 0, "Software\\F", Some("*"), None),
        ]
    );
}

/// Read-only: the cached packages of the products installed on this host. Nothing is installed,
/// repaired or changed; the databases are opened read-only.
#[test]
fn host_installed_packages_read_only() {
    use purge_win::msi::{EnumScope, enum_products, product_info};
    let products = enum_products(EnumScope::CurrentUser).expect("MsiEnumProductsExW");
    let started = Instant::now();
    let (mut ok, mut failed, mut truncated, mut no_code) = (0, 0, 0, 0);
    for p in &products {
        let Ok(info) = product_info(p) else { continue };
        let Some(pkg) = info.local_package else {
            continue;
        };
        let pkg = PathBuf::from(pkg);
        if !pkg.is_file() {
            continue;
        }
        match read_tables(&pkg, &TableLimits::default()) {
            Ok(t) => {
                ok += 1;
                truncated += usize::from(t.truncated);
                if !t.properties.iter().any(|(n, _)| n == "ProductCode") {
                    no_code += 1;
                }
            }
            Err(e) => {
                failed += 1;
                println!("{} {}: {e}", p.product_code, pkg.display());
            }
        }
    }
    println!(
        "{} products: {ok} packages read, {failed} unreadable, {truncated} truncated, {no_code} without ProductCode, in {:?}",
        products.len(),
        started.elapsed()
    );
    assert_eq!(no_code, 0, "every MSI package defines ProductCode");
}
