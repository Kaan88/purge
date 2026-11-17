//! Machine and app shapes shared by the M1b harvest tests. Everything here uses only what the M1a
//! harvest also had (the fixture builder, the inventory), so the same shapes give the M1a golden
//! documents in `tests/data/m1b/`.

use purge_model::object::{TaskAction, TaskIdentity};
use purge_source::fixture::{Fixture, FixtureBuilder};
use purge_source::sysobj::TaskInfo;
use purge_source::types::KnownFolder;

/// The interactive user.
pub const SID: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";
/// The Uninstall key of the machine, 64-bit view.
pub const UNINSTALL: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
/// The Services key, as the fixture stores it.
pub const SERVICES: &str = r"HKLM\SYSTEM\ControlSet001\Services";
/// The firewall rules key, as the fixture stores it.
pub const FIREWALL: &str =
    r"HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

/// A machine with one user, the usual folders, and empty Services and FirewallRules keys.
pub fn machine() -> FixtureBuilder {
    Fixture::builder()
        .os("Professional", 26100, 1742)
        .user_sid(SID)
        .profile(SID, r"C:\Users\tester")
        .env("USERNAME", "tester")
        .env("SYSTEMDRIVE", "C:")
        .env("WINDIR", r"C:\Windows")
        .env("SYSTEMROOT", r"C:\Windows")
        .env("PROGRAMFILES", r"C:\Program Files")
        .env("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
        .env("PROGRAMDATA", r"C:\ProgramData")
        .env("PUBLIC", r"C:\Users\Public")
        .env("APPDATA", r"C:\Users\tester\AppData\Roaming")
        .env("LOCALAPPDATA", r"C:\Users\tester\AppData\Local")
        .known_folder(KnownFolder::Documents, r"C:\Users\tester\Documents")
        .admin_only_roots(&[
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            r"C:\Windows",
        ])
        .volume(r"C:\", Some(0xAABB_CCDD), true, "NTFS")
        .key(SERVICES)
        .key(FIREWALL)
        .key(r"HKU\S-1-5-21-1004336348-1177238915-682003330-1001\Software")
        .now(134_000_000_000_000_000)
}

/// A service with an `ImagePath`, own-process, demand start, LocalSystem.
pub fn service(b: FixtureBuilder, name: &str, image_path: &str) -> FixtureBuilder {
    let key = format!(r"{SERVICES}\{name}");
    b.expand_sz(&key, "ImagePath", image_path)
        .dword(&key, "Type", 0x10)
        .dword(&key, "Start", 3)
        .sz(&key, "ObjectName", "LocalSystem")
        .sz(&key, "DisplayName", name)
}

/// A firewall rule of the local store.
pub fn firewall_rule(b: FixtureBuilder, id: &str, name: &str, app: &str) -> FixtureBuilder {
    b.sz(
        FIREWALL,
        id,
        &format!("v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App={app}|Name={name}|"),
    )
}

/// A scheduled task with exec actions.
pub fn task(path: &str, programs: &[&str]) -> TaskInfo {
    TaskInfo {
        identity: TaskIdentity {
            path: path.to_owned(),
            actions: programs
                .iter()
                .map(|p| TaskAction::Exec {
                    path: (*p).to_owned(),
                    arguments: None,
                    working_dir: None,
                })
                .collect(),
        },
        enabled: true,
        hidden: false,
        author: None,
        stored_password: false,
        run_as: None,
    }
}

/// Another app that owns a service, a firewall rule and a task in its own folder.
pub fn other_app(b: FixtureBuilder) -> FixtureBuilder {
    let key = format!(r"{UNINSTALL}\Other");
    let b = b
        .sz(&key, "DisplayName", "Other Tool")
        .sz(&key, "InstallLocation", r"C:\Program Files\Other")
        .sz(
            &key,
            "UninstallString",
            r#""C:\Program Files\Other\uninst.exe""#,
        )
        .file(r"C:\Program Files\Other\uninst.exe", 10)
        .file(r"C:\Program Files\Other\other.exe", 10)
        .file(r"C:\Program Files\Other\othersvc.exe", 10)
        .task(task(
            r"\Other\Update",
            &[r"C:\Program Files\Other\other.exe"],
        ));
    let b = service(b, "OtherSvc", r#""C:\Program Files\Other\othersvc.exe""#);
    firewall_rule(
        b,
        "{0000AAAA-0000-0000-0000-000000000001}",
        "Other Tool",
        r"C:\Program Files\Other\other.exe",
    )
}

/// An Inno-shaped app with `InstallLocation`, beside [`other_app`]; it owns no system object.
pub fn inno_shape() -> Fixture {
    let app = r"C:\Program Files\Tool";
    let key = format!(r"{UNINSTALL}\Tool_is1");
    let b = machine()
        .sz(&key, "DisplayName", "Tool")
        .sz(&key, "Publisher", "Tool Makers")
        .sz(&key, "InstallLocation", &format!("{app}\\"))
        .sz(&key, "DisplayIcon", &format!(r"{app}\tool.exe"))
        .sz(&key, "UninstallString", &format!(r#""{app}\unins000.exe""#))
        .file(&format!(r"{app}\tool.exe"), 1_000)
        .file(&format!(r"{app}\unins000.exe"), 1_000)
        .file(&format!(r"{app}\lib\core.dll"), 1_000)
        .sz(
            r"HKLM\SOFTWARE\Classes\Tool.Doc\shell\open\command",
            "",
            &format!(r#""{app}\tool.exe" "%1""#),
        )
        .sz(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\tool.exe",
            "",
            &format!(r"{app}\tool.exe"),
        );
    other_app(b).build()
}

/// An NSIS-shaped app with only `DisplayIcon` and its uninstaller (an inferred root), beside
/// [`other_app`]; a service named like it runs from another folder.
pub fn nsis_shape() -> Fixture {
    let app = r"C:\Program Files (x86)\Editor";
    let key = format!(r"{UNINSTALL}\Editor");
    let b = machine()
        .sz(&key, "DisplayName", "Editor")
        .sz(&key, "DisplayIcon", &format!(r"{app}\editor.exe,0"))
        .sz(
            &key,
            "UninstallString",
            &format!(r#""{app}\uninstall.exe""#),
        )
        .file(&format!(r"{app}\editor.exe"), 1_000)
        .file(&format!(r"{app}\uninstall.exe"), 1_000);
    let b = service(b, "Editor", r#""C:\Program Files\Other\other.exe""#);
    other_app(b).build()
}

/// The M1a shapes with the display name of the entry to harvest and the golden file's name.
pub fn m1a_shapes() -> Vec<(&'static str, &'static str, Fixture)> {
    vec![
        ("Tool", "m1a-inno.json", inno_shape()),
        ("Editor", "m1a-nsis.json", nsis_shape()),
    ]
}
