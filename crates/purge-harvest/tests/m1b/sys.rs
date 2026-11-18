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

/// Hostile (smoke trap svc-svchost): a service hosted by svchost whose `ServiceDll` is a file in the
/// app's root shares a Windows process; the guard judges it by its host and it is not recorded.
#[test]
fn sys_service_svchost_with_dll_in_root_not_recorded() {
    let key = r"HKLM\SYSTEM\ControlSet001\Services\ToolSvcHost";
    let b = service(
        tool().file(&format!(r"{APP}\toolhost.dll"), 1_000),
        "ToolSvcHost",
        r"%SystemRoot%\System32\svchost.exe -k ToolGroup",
    )
    .expand_sz(
        &format!(r"{key}\Parameters"),
        "ServiceDll",
        &format!(r"{APP}\toolhost.dll"),
    )
    .dword(key, "Type", 0x20);
    let report = harvest_of(&b.build(), "Tool");
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

/// R4 B2: a task whose only action is a COM handler of the app's own class (its `InprocServer32` is a
/// file in the app's InstallRoot: an anchor) is recorded, with no program and `AppComClass`. A
/// COM-only task of a class that is not the app's, one that mixes the app's class with another, and one
/// whose handler names no CLSID are not.
#[test]
fn sys_task_com_handler_of_the_apps_class_recorded() {
    const OWN: &str = "{0A0A0A0A-0000-4000-8000-00000000C0DE}";
    const FOREIGN: &str = "{0F0F0F0F-0000-0000-0000-000000000001}";
    let com = |path: &str, clsids: &[&str]| {
        let mut t = task(path, &[]);
        t.identity.actions = clsids
            .iter()
            .map(|c| TaskAction::ComHandler {
                clsid: (*c).to_owned(),
                data: Some("notify".into()),
            })
            .collect();
        t
    };
    let b = tool()
        .file(&format!(r"{APP}\toolcom.dll"), 1_000)
        .sz(
            &format!(r"HKLM\SOFTWARE\Classes\CLSID\{OWN}\InprocServer32"),
            "",
            &format!(r"{APP}\toolcom.dll"),
        )
        .file(r"C:\Program Files\Other\othercom.dll", 1_000)
        .sz(
            &format!(r"HKLM\SOFTWARE\Classes\CLSID\{FOREIGN}\InprocServer32"),
            "",
            r"C:\Program Files\Other\othercom.dll",
        )
        .task(com(r"\Tool\Notify", &[OWN]))
        .task(com(r"\Tool\NotifyTwice", &[OWN, OWN]))
        .task(com(r"\Tool\Foreign", &[FOREIGN]))
        .task(com(r"\Tool\Both", &[OWN, FOREIGN]))
        .task(com(r"\Tool\NoClass", &[" "]));
    let report = harvest_of(&b.build(), "Tool");
    let clsids = &report.fingerprint.anchors.clsids;
    assert!(
        clsids.iter().any(|c| c.eq_ignore_ascii_case(OWN)),
        "{clsids:?}"
    );
    assert!(
        !clsids.iter().any(|c| c.eq_ignore_ascii_case(FOREIGN)),
        "{clsids:?}"
    );
    let tasks = &report.fingerprint.sys.tasks;
    assert_eq!(
        tasks
            .iter()
            .map(|t| (t.identity.path.as_str(), t.why, t.program.as_deref()))
            .collect::<Vec<_>>(),
        [
            (r"\Tool\Notify", ObjectWhy::AppComClass, None),
            (r"\Tool\NotifyTwice", ObjectWhy::AppComClass, None),
        ]
    );
    // The identity, with the handler's data, is what the scan compares.
    assert_eq!(tasks[0].identity, com(r"\Tool\Notify", &[OWN]).identity);
}

/// R4 B2 (hostile): the app's class under a task path of Windows' own is still refused by the guard.
#[test]
fn sys_task_com_handler_windows_path_not_recorded() {
    const OWN: &str = "{0A0A0A0A-0000-4000-8000-00000000C0DE}";
    let mut t = task(r"\Microsoft\Windows\Tool\Notify", &[]);
    t.identity.actions = vec![TaskAction::ComHandler {
        clsid: OWN.into(),
        data: None,
    }];
    let b = tool()
        .file(&format!(r"{APP}\toolcom.dll"), 1_000)
        .sz(
            &format!(r"HKLM\SOFTWARE\Classes\CLSID\{OWN}\InprocServer32"),
            "",
            &format!(r"{APP}\toolcom.dll"),
        )
        .task(t);
    let report = harvest_of(&b.build(), "Tool");
    assert!(
        report
            .fingerprint
            .anchors
            .clsids
            .iter()
            .any(|c| c.eq_ignore_ascii_case(OWN))
    );
    assert!(
        report.fingerprint.sys.tasks.is_empty(),
        "{:?}",
        report.fingerprint.sys.tasks
    );
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

/// R2a S4 (hostile): an entry with only a `DisplayIcon` gets an inferred root. Another tool's service,
/// task and rule running a program in that folder are not the app's.
#[test]
fn sys_objects_in_an_inferred_root_not_recorded() {
    let dir = r"C:\Tools\bin";
    let key = format!(r"{UNINSTALL}\IconOnly");
    let b = machine()
        .sz(&key, "DisplayName", "Icon Only")
        .sz(&key, "DisplayIcon", &format!(r"{dir}\icononly.exe,0"))
        .file(&format!(r"{dir}\icononly.exe"), 1_000)
        .file(&format!(r"{dir}\other.exe"), 1_000)
        .task(task(r"\Other\InBin", &[&format!(r"{dir}\other.exe")]));
    let b = service(b, "OtherInBin", &format!(r#""{dir}\other.exe""#));
    let b = firewall_rule(
        b,
        "{0000BBBB-0000-0000-0000-000000000001}",
        "Other in bin",
        &format!(r"{dir}\other.exe"),
    );
    let report = harvest_of(&b.build(), "Icon Only");
    let fp = &report.fingerprint;
    assert!(
        fp.roots
            .iter()
            .any(|r| r.kind == purge_model::RootKind::InferredRoot && r.path == dir),
        "{:?}",
        fp.roots
    );
    assert!(fp.sys.services.is_empty(), "{:?}", fp.sys.services);
    assert!(fp.sys.tasks.is_empty(), "{:?}", fp.sys.tasks);
    assert!(
        fp.sys.firewall_rules.is_empty(),
        "{:?}",
        fp.sys.firewall_rules
    );
}

/// R2a S5 (hostile): a host found inside the app's folder, a host named without `.exe`, and a program
/// of the app whose argument names another product's code.
#[test]
fn sys_hosts_and_foreign_arguments_not_recorded() {
    let b = tool()
        .file(&format!(r"{APP}\dotnet.exe"), 1_000)
        .file(&format!(r"{APP}\launcher.exe"), 1_000);
    let b = service(
        b,
        "DotnetHosted",
        &format!(r#""{APP}\dotnet.exe" "C:\Program Files\Other\svc.dll""#),
    );
    let b = service(b, "BareHost", &format!(r"{APP}\python scripts\run.bat"));
    let b = service(
        b,
        "Launched",
        &format!(r#""{APP}\launcher.exe" C:\Program Files\Other\other.exe"#),
    );
    let b = service(
        b,
        "LaunchedUnc",
        &format!(r#""{APP}\launcher.exe" \\srv\s\x.dll"#),
    );
    // The app's own program with an argument in its own folder is the app's.
    let b = service(
        b,
        "ToolUpdater",
        &format!(r#""{APP}\update.exe" --config "{APP}\update.ini""#),
    );
    let mut launched = task(r"\Tool\Launched", &[&format!(r"{APP}\launcher.exe")]);
    if let TaskAction::Exec { arguments, .. } = &mut launched.identity.actions[0] {
        *arguments = Some(r#"-load "C:\Program Files\Other\other.dll""#.to_owned());
    }
    let b = b.task(launched);
    let report = harvest_of(&b.build(), "Tool");
    let fp = &report.fingerprint;
    assert_eq!(
        fp.sys
            .services
            .iter()
            .map(|s| s.identity.name.as_str())
            .collect::<Vec<_>>(),
        ["ToolUpdater"]
    );
    assert!(fp.sys.tasks.is_empty(), "{:?}", fp.sys.tasks);
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
