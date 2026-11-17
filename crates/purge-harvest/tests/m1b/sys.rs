//! System objects recorded at harvest: services, tasks and firewall rules whose program is the app's.

use purge_model::object::TaskAction;
use purge_model::{ObjectWhy, RootSource};
use purge_source::fixture::FixtureBuilder;
use purge_source::sysobj::{MsiServiceRaw, MsiTables};

use super::msi::{TOOL, component_row};
use super::shapes::{firewall_rule, other_app, service, task};
use super::*;

const APP: &str = r"C:\Program Files\Tool";

/// A non-MSI app with `InstallLocation` = [`APP`], beside the other app of the shapes.
fn tool() -> FixtureBuilder {
    let key = format!(r"{UNINSTALL}\Tool");
    let b = machine()
        .sz(&key, "DisplayName", "Tool")
        .sz(&key, "InstallLocation", APP)
        .sz(
            &key,
            "UninstallString",
            &format!(r#""{APP}\uninstall.exe""#),
        )
        .file(&format!(r"{APP}\tool.exe"), 1_000)
        .file(&format!(r"{APP}\toolsvc.exe"), 1_000)
        .file(&format!(r"{APP}\update.exe"), 1_000)
        .file(&format!(r"{APP}\python.exe"), 1_000)
        .file(&format!(r"{APP}\uninstall.exe"), 1_000);
    other_app(b)
}

/// An MSI app with two key-path files in [`APP`] and a `ServiceInstall` row named `ToolSvc`.
fn msi_tool() -> FixtureBuilder {
    let b = msi_app(machine(), TOOL, "Tool", None);
    let b = files(
        b,
        TOOL,
        1,
        &[&format!(r"{APP}\tool.exe"), &format!(r"{APP}\toolsvc.exe")],
    );
    // One more key path, in the Windows folder: the app's file, outside every root.
    let b = files(b, TOOL, 5, &[r"C:\Windows\toolhelper.exe"]);
    let b = with_tables(
        b,
        TOOL,
        MsiTables {
            components: vec![component_row("Svc", &comp(2))],
            service_install: vec![MsiServiceRaw {
                name: "ToolSvc".into(),
                component: "Svc".into(),
                service_type: 0x10,
                start_type: 2,
            }],
            ..MsiTables::default()
        },
    );
    other_app(b)
}

#[test]
fn sys_service_program_in_root_recorded() {
    let b = service(
        tool(),
        "ToolUpdater",
        &format!(r#""{APP}\update.exe" --service"#),
    );
    let report = harvest_of(&b.build(), "Tool");
    let services = &report.fingerprint.sys.services;
    assert_eq!(services.len(), 1, "{services:?}");
    assert_eq!(services[0].identity.name, "ToolUpdater");
    assert_eq!(services[0].why, ObjectWhy::ProgramInRoot);
    assert_eq!(
        services[0].program.as_deref(),
        Some(format!(r"{APP}\update.exe").as_str())
    );

    // The service of the app's own MSI, running from its root.
    let b = service(msi_tool(), "ToolSvc", &format!(r#""{APP}\toolsvc.exe""#));
    let report = harvest_of(&b.build(), "Tool");
    assert_eq!(roots(&report), [(APP.to_owned(), RootSource::MsiComponent)]);
    assert_eq!(report.fingerprint.msi[0].services[0].name, "ToolSvc");
    let services = &report.fingerprint.sys.services;
    assert_eq!(services.len(), 1, "{services:?}");
    assert_eq!(services[0].why, ObjectWhy::MsiServiceRow);
}

#[test]
fn sys_service_name_match_only_not_recorded() {
    // Hostile: services named like the app and like its MSI ServiceInstall row, running another
    // app's program.
    let b = service(
        msi_tool(),
        "ToolSvc",
        r#""C:\Program Files\Other\othersvc.exe""#,
    );
    let b = service(b, "Tool", r#""C:\Program Files\Other\other.exe" /tool"#);
    let report = harvest_of(&b.build(), "Tool");
    assert!(
        report.fingerprint.sys.services.is_empty(),
        "{:?}",
        report.fingerprint.sys.services
    );
}

#[test]
fn sys_service_under_systemroot_not_recorded() {
    // The app's own key-path file in the Windows folder runs as a service: the guard keeps every
    // service whose program is under %SystemRoot%, so it is not recorded.
    let b = service(msi_tool(), "ToolHelper", r"C:\Windows\toolhelper.exe");
    // A svchost service whose DLL is in the Windows folder.
    let key = r"HKLM\SYSTEM\ControlSet001\Services\ToolHost";
    let b = service(
        b,
        "ToolHost",
        r"%SystemRoot%\System32\svchost.exe -k netsvcs",
    )
    .expand_sz(
        &format!(r"{key}\Parameters"),
        "ServiceDll",
        r"%SystemRoot%\System32\toolhost.dll",
    )
    .dword(key, "Type", 0x20);
    let report = harvest_of(&b.build(), "Tool");
    assert!(outside(&report).contains(&r"C:\Windows\toolhelper.exe".to_owned()));
    assert!(
        report.fingerprint.sys.services.is_empty(),
        "{:?}",
        report.fingerprint.sys.services
    );
}

#[test]
fn sys_task_all_actions_must_be_owned() {
    let tool_exe = format!(r"{APP}\tool.exe");
    let update = format!(r"{APP}\update.exe");
    let b = tool()
        .task(task(r"\Tool\Update", &[&update, &tool_exe]))
        .task(task(
            r"\Tool\Mixed",
            &[&update, r"C:\Program Files\Other\other.exe"],
        ));
    // An exec action of the app and a COM handler of somebody else.
    let mut com = task(r"\Tool\WithCom", &[&update]);
    com.identity.actions.push(TaskAction::ComHandler {
        clsid: "{0F0F0F0F-0000-0000-0000-000000000001}".into(),
        data: None,
    });
    let b = b.task(com);
    let report = harvest_of(&b.build(), "Tool");
    let tasks = &report.fingerprint.sys.tasks;
    assert_eq!(
        tasks
            .iter()
            .map(|t| t.identity.path.as_str())
            .collect::<Vec<_>>(),
        [r"\Tool\Update"]
    );
    assert_eq!(tasks[0].why, ObjectWhy::ProgramInRoot);
    assert_eq!(tasks[0].program.as_deref(), Some(update.as_str()));
}

#[test]
fn sys_task_interpreter_action_not_recorded() {
    let mut script = task(r"\Tool\Script", &[r"C:\Windows\System32\cmd.exe"]);
    if let TaskAction::Exec { arguments, .. } = &mut script.identity.actions[0] {
        *arguments = Some(format!(r#"/c "{APP}\update.bat""#));
    }
    let mut ps = task(r"\Tool\Ps", &[r"powershell.exe"]);
    if let TaskAction::Exec { arguments, .. } = &mut ps.identity.actions[0] {
        *arguments = Some(format!(r#"-File "{APP}\update.ps1""#));
    }
    // An interpreter shipped inside the app's own folder is still an interpreter.
    let bundled = task(r"\Tool\Bundled", &[&format!(r"{APP}\python.exe")]);
    let b = tool().task(script).task(ps).task(bundled);
    let report = harvest_of(&b.build(), "Tool");
    assert!(
        report.fingerprint.sys.tasks.is_empty(),
        "{:?}",
        report.fingerprint.sys.tasks
    );
}

#[test]
fn sys_firewall_rule_app_in_root_recorded_other_rule_same_name_not() {
    let ours = "{0000BBBB-0000-0000-0000-000000000001}";
    let b = firewall_rule(tool(), ours, "Tool", &format!(r"{APP}\tool.exe"));
    // Hostile: a rule with the same name for another program.
    let b = firewall_rule(
        b,
        "{0000BBBB-0000-0000-0000-000000000002}",
        "Tool",
        r"C:\Program Files\Other\tool.exe",
    );
    // A Windows-style resource-named rule and a package-bound rule for the app's program.
    let b = firewall_rule(
        b,
        "{0000BBBB-0000-0000-0000-000000000003}",
        "@tool.dll,-100",
        &format!(r"{APP}\tool.exe"),
    );
    let b = b.sz(
        super::shapes::FIREWALL,
        "{0000BBBB-0000-0000-0000-000000000004}",
        &format!(
            r"v2.31|Action=Allow|Active=TRUE|Dir=In|App={APP}\tool.exe|PFN=Tool_abc|Name=Tool Store|"
        ),
    );
    let report = harvest_of(&b.build(), "Tool");
    let rules = &report.fingerprint.sys.firewall_rules;
    assert_eq!(
        rules
            .iter()
            .map(|r| r.identity.id.as_str())
            .collect::<Vec<_>>(),
        [ours]
    );
    assert_eq!(rules[0].why, ObjectWhy::ProgramInRoot);
}

#[test]
fn sys_objects_identity_digest_stored() {
    let b = service(tool(), "ToolUpdater", &format!(r#""{APP}\update.exe""#))
        .task(task(r"\Tool\Update", &[&format!(r"{APP}\update.exe")]));
    let b = firewall_rule(
        b,
        "{0000BBBB-0000-0000-0000-000000000001}",
        "Tool",
        &format!(r"{APP}\tool.exe"),
    );
    let f = b.build();
    let report = harvest_of(&f, "Tool");
    let sys = &report.fingerprint.sys;
    assert_eq!(
        (
            sys.services.len(),
            sys.tasks.len(),
            sys.firewall_rules.len()
        ),
        (1, 1, 1)
    );
    // The identities are stored as read, so their digests are those of the objects on the machine.
    let index = purge_index::sysobj::build(&f, &f);
    let svc = index
        .services
        .iter()
        .find(|s| s.identity.name == "ToolUpdater")
        .unwrap();
    assert_eq!(sys.services[0].identity, svc.identity);
    assert_eq!(sys.services[0].identity.fp(), svc.identity.fp());
    let t = index
        .tasks
        .iter()
        .find(|t| t.identity.path == r"\Tool\Update")
        .unwrap();
    assert_eq!(sys.tasks[0].identity.fp(), t.identity.fp());
    let r = index
        .firewall
        .iter()
        .find(|r| r.identity.id == "{0000BBBB-0000-0000-0000-000000000001}")
        .unwrap();
    assert_eq!(sys.firewall_rules[0].identity.fp(), r.identity.fp());
    assert_eq!(sys.firewall_rules[0].identity.rule, r.identity.rule);
    // The digest survives the document's round trip.
    let json = purge_harvest::harvest::to_json(&report.fingerprint);
    let back: purge_model::Fingerprint = serde_json::from_str(&json).unwrap();
    assert_eq!(back.sys.services[0].identity.fp(), svc.identity.fp());
    assert_eq!(back.sys, *sys);
}
