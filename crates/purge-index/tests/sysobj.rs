//! System-object index tests (C-SYSOBJ): service and firewall readers over `RegistrySource`, task
//! programs, and `resolve_program`.

use std::path::Path;
use std::sync::Mutex;

use purge_index::sysobj::{
    self, Env, FIREWALL_RULES_KEY, FirewallFacts, ProgramRef, SERVICES_KEY, ServiceFacts,
    SysObjectIndex, read_firewall, read_services, resolve_file, resolve_program, task_programs,
};
use purge_model::object::{TaskAction, TaskIdentity};
use purge_source::fixture::{Coverage, CoverageRoot, Fixture, FixtureBuilder};
use purge_source::registry::RegistrySource;
use purge_source::sysobj::TaskInfo;
use purge_source::types::{KeyInfo, RegData, RegValue, SourceResult};

const SVC: &str = r"HKLM\SYSTEM\ControlSet001\Services";
const FW: &str =
    r"HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

fn machine() -> Fixture {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/sysobj/machine.json");
    Fixture::from_json_file(&path).expect("machine.json loads")
}

fn env() -> Env {
    Env::new([
        ("SystemRoot", r"C:\WINDOWS"),
        ("windir", r"C:\WINDOWS"),
        ("ProgramFiles", r"C:\Program Files"),
    ])
}

fn file(path: &str) -> ProgramRef {
    ProgramRef::File(path.to_owned())
}

fn unresolved(raw: &str) -> ProgramRef {
    ProgramRef::Unresolved {
        raw: raw.to_owned(),
    }
}

fn index() -> SysObjectIndex {
    let fx = machine();
    sysobj::build(&fx, &fx)
}

fn service<'a>(index: &'a SysObjectIndex, name: &str) -> &'a ServiceFacts {
    index
        .services
        .iter()
        .find(|s| s.identity.name == name)
        .unwrap_or_else(|| panic!("service {name} read"))
}

fn rule<'a>(index: &'a SysObjectIndex, id_suffix: &str) -> &'a FirewallFacts {
    index
        .firewall
        .iter()
        .find(|r| r.identity.id.ends_with(id_suffix))
        .unwrap_or_else(|| panic!("rule {id_suffix} read"))
}

/// Services read from a builder fixture with one service of the given `ImagePath`.
fn one_service(name: &str, image_path: &str, ty: u32) -> ServiceFacts {
    let key = format!(r"{SVC}\{name}");
    let fx = Fixture::builder()
        .expand_sz(&key, "ImagePath", image_path)
        .dword(&key, "Type", ty)
        .dword(&key, "Start", 3)
        .build();
    let mut errors = Vec::new();
    let mut services = read_services(&fx, &env(), &mut errors).expect("services read");
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(services.len(), 1);
    services.remove(0)
}

fn rules(rules: &[(&str, &str)]) -> Vec<FirewallFacts> {
    let mut b = Fixture::builder();
    for (id, rule) in rules {
        b = b.sz(FW, id, rule);
    }
    let fx = b.build();
    let mut errors = Vec::new();
    let out = read_firewall(&fx, &env(), &mut errors).expect("rules read");
    assert!(errors.is_empty(), "{errors:?}");
    out
}

// ---------------------------------------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------------------------------------

#[test]
fn svc_quoted_path_with_args() {
    let env = env();
    assert_eq!(
        resolve_program(
            r#""C:\Program Files\App\svc.exe" -run --conf "C:\Other Product\x.exe""#,
            &env
        ),
        file(r"C:\Program Files\App\svc.exe")
    );
    assert_eq!(
        resolve_program(r#""%ProgramFiles%\App\svc.exe""#, &env),
        file(r"C:\Program Files\App\svc.exe")
    );
    // A quote that is never closed names no program.
    let open = r#""C:\Program Files\App\svc.exe -run"#;
    assert_eq!(resolve_program(open, &env), unresolved(open));

    let index = index();
    let app = service(&index, "AppSvc");
    assert_eq!(app.program, file(r"C:\Program Files\App\svc.exe"));
    assert!(!app.svchost && !app.is_driver && !app.per_user_template);
    assert_eq!(
        app.identity.image_path.as_deref(),
        Some(r#""C:\Program Files\App\svc.exe" -run"#)
    );
    assert_eq!(app.identity.service_type, 16);
    assert_eq!(app.identity.start, 2);
    assert_eq!(app.identity.object_name.as_deref(), Some("LocalSystem"));
    assert_eq!(app.identity.service_dll, None);
    assert_eq!(app.display_name.as_deref(), Some("App Service"));
}

#[test]
fn svc_unquoted_path_with_spaces_single_candidate() {
    let env = env();
    for (raw, want) in [
        (
            r"C:\Program Files\App\helper.exe",
            r"C:\Program Files\App\helper.exe",
        ),
        (
            r"C:\Program Files\App\svc.exe -k group /x C:\Other\y.exe",
            r"C:\Program Files\App\svc.exe",
        ),
        (
            r"C:\Program Files\App Data\svc.exe run",
            r"C:\Program Files\App Data\svc.exe",
        ),
        (
            r"%ProgramFiles%\App\svc.exe --service",
            r"C:\Program Files\App\svc.exe",
        ),
        (
            r"C:\Program Files\Vendor\drv.sys",
            r"C:\Program Files\Vendor\drv.sys",
        ),
        (
            r"C:/Program Files/App/svc.exe",
            r"C:\Program Files\App\svc.exe",
        ),
    ] {
        assert_eq!(resolve_program(raw, &env), file(want), "{raw}");
    }
    let helper = service(&index(), "AppHelper").clone();
    assert_eq!(helper.program, file(r"C:\Program Files\App\helper.exe"));
}

/// Hostile: an unquoted path where more than one prefix ends in a program extension. Windows runs the
/// first that exists (`C:\Program.exe` before `C:\Program Files\...`), so either could be the program.
#[test]
fn svc_unquoted_ambiguous_is_unresolved() {
    let env = env();
    for raw in [
        r"C:\Program.exe Files\A B\c.exe",
        r"C:\Program Files\A.exe B\c.exe",
        r"C:\Program Files\Other.exe C:\Program Files\App\svc.exe",
        r"C:\Program Files\A.exe B\drv.sys",
        r"C:\App\svc.exe C:\Data\x.exe",
        // A blank and no program extension: where the name ends cannot be told.
        r"C:\Program Files\App\tool -x",
        r"C:\Program Files\App\tool",
    ] {
        assert_eq!(resolve_program(raw, &env), unresolved(raw), "{raw}");
    }
    let raw = r"C:\Program Files\Other.exe C:\Program Files\App\svc.exe";
    assert_eq!(one_service("Hostile", raw, 16).program, unresolved(raw));
}

#[test]
fn svc_systemroot_and_nt_prefixes() {
    let env = env();
    for (raw, want) in [
        (
            r"\SystemRoot\System32\drivers\appdrv.sys",
            r"C:\WINDOWS\System32\drivers\appdrv.sys",
        ),
        (
            r"\systemroot\system32\drivers\x.sys",
            r"C:\WINDOWS\system32\drivers\x.sys",
        ),
        (
            r"System32\drivers\x.sys",
            r"C:\WINDOWS\System32\drivers\x.sys",
        ),
        (r"system32\x.exe -a", r"C:\WINDOWS\system32\x.exe"),
        (
            r"\??\C:\Program Files\App\k.sys",
            r"C:\Program Files\App\k.sys",
        ),
        (r"\\?\C:\App\x.exe", r"C:\App\x.exe"),
        (r"%SystemRoot%\x\y.exe", r"C:\WINDOWS\x\y.exe"),
        (r"%windir%\x\y.exe", r"C:\WINDOWS\x\y.exe"),
    ] {
        assert_eq!(resolve_program(raw, &env), file(want), "{raw}");
    }
    for raw in [
        r"drivers\x.sys",
        r"x.exe",
        r"\Device\HarddiskVolume3\x.sys",
        r"\\server\share\x.exe",
        r"\\.\C:\x.exe",
        r"%NOPE%\x.exe",
        r"C:\App\%NOPE%\x.exe",
        r"C:\PROGRA~1\App\x.exe",
        r"C:\App\..\Other\x.exe",
        r"C:\x.exe:stream",
        r"C:\",
    ] {
        assert_eq!(resolve_program(raw, &env), unresolved(raw), "{raw}");
    }
    // Without the Windows directory in the environment nothing below it is known.
    let bare = Env::default();
    let raw = r"\SystemRoot\System32\drivers\x.sys";
    assert_eq!(resolve_program(raw, &bare), unresolved(raw));
    assert_eq!(resolve_program("  ", &env), ProgramRef::None);

    let drv = service(&index(), "appdrv").clone();
    assert_eq!(drv.program, file(r"C:\WINDOWS\System32\drivers\appdrv.sys"));
}

#[test]
fn svc_svchost_uses_servicedll() {
    let index = index();
    let dns = service(&index, "Dnscache");
    assert!(dns.svchost);
    assert_eq!(dns.program, file(r"C:\WINDOWS\System32\dnsrslvr.dll"));
    // The identity keeps the strings as stored.
    assert_eq!(
        dns.identity.service_dll.as_deref(),
        Some(r"%SystemRoot%\System32\dnsrslvr.dll")
    );
    assert_eq!(
        dns.identity.image_path.as_deref(),
        Some(r"%SystemRoot%\system32\svchost.exe -k NetworkService -p")
    );
    assert_eq!(
        service(&index, "RpcSs").program,
        file(r"C:\WINDOWS\system32\rpcss.dll")
    );

    // The top-level ServiceDll counts when Parameters has none; Parameters wins when both exist.
    let key = format!(r"{SVC}\Mixed");
    let top = format!(r"{SVC}\Top");
    let fx = Fixture::builder()
        .expand_sz(
            &key,
            "ImagePath",
            r"%SystemRoot%\System32\svchost.exe -k netsvcs -p",
        )
        .dword(&key, "Type", 32)
        .expand_sz(&key, "ServiceDll", r"C:\Program Files\Other\other.dll")
        .expand_sz(
            &format!(r"{key}\Parameters"),
            "ServiceDll",
            r"C:\Program Files\App\svc.dll",
        )
        .expand_sz(&top, "ImagePath", r"C:\WINDOWS\SysWOW64\svchost.exe -k x")
        .dword(&top, "Type", 32)
        .expand_sz(&top, "ServiceDll", r"C:\Program Files\App\top.dll")
        .build();
    let mut errors = Vec::new();
    let services = read_services(&fx, &env(), &mut errors).unwrap();
    assert!(errors.is_empty(), "{errors:?}");
    let by = |n: &str| services.iter().find(|s| s.identity.name == n).unwrap();
    assert_eq!(by("Mixed").program, file(r"C:\Program Files\App\svc.dll"));
    assert_eq!(
        by("Mixed").identity.service_dll.as_deref(),
        Some(r"C:\Program Files\App\svc.dll")
    );
    assert_eq!(by("Top").program, file(r"C:\Program Files\App\top.dll"));
    assert!(by("Top").svchost);
}

#[test]
fn svc_svchost_without_servicedll_unresolved() {
    let index = index();
    let instance = service(&index, "CDPUserSvc_4a5b1");
    assert!(instance.svchost);
    assert_eq!(
        instance.program,
        unresolved(r"C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup")
    );

    // A file named svchost.exe outside the Windows directory does not load a ServiceDll: it is a host
    // executable like any other, and the DLL it names says nothing about whose service it is.
    let key = format!(r"{SVC}\Fake");
    let raw = r"C:\Program Files\Other\svchost.exe -k x";
    let fx = Fixture::builder()
        .expand_sz(&key, "ImagePath", raw)
        .dword(&key, "Type", 16)
        .expand_sz(
            &format!(r"{key}\Parameters"),
            "ServiceDll",
            r"C:\Program Files\App\a.dll",
        )
        .build();
    let mut errors = Vec::new();
    let services = read_services(&fx, &env(), &mut errors).unwrap();
    assert!(services[0].svchost);
    assert_eq!(services[0].program, unresolved(raw));

    // An empty ServiceDll is no DLL.
    let key = format!(r"{SVC}\Empty");
    let raw = r"%SystemRoot%\System32\svchost.exe -k x";
    let fx = Fixture::builder()
        .expand_sz(&key, "ImagePath", raw)
        .dword(&key, "Type", 32)
        .expand_sz(&format!(r"{key}\Parameters"), "ServiceDll", "")
        .build();
    let services = read_services(&fx, &env(), &mut errors).unwrap();
    assert_eq!(services[0].program, unresolved(raw));
}

/// Hostile: an interpreter or host whose argument is a path inside the app's root is not the app's
/// program; argument-only attribution is never Tier A.
#[test]
fn svc_interpreter_with_app_path_argument_unresolved() {
    let env = env();
    for raw in [
        r#""C:\Program Files\nodejs\node.exe" "C:\Program Files\App\server.js""#,
        r#"C:\WINDOWS\System32\cmd.exe /c "C:\Program Files\App\run.bat""#,
        r"cmd /c C:\App\run.bat",
        r"powershell -ExecutionPolicy Bypass -File C:\App\svc.ps1",
        r#"%SystemRoot%\System32\WindowsPowerShell\v1.0\PowerShell.exe -File "C:\Program Files\App\x.ps1""#,
        r#"rundll32.exe "C:\Program Files\App\x.dll",Run"#,
        r"C:\WINDOWS\system32\msiexec.exe /V",
        r"C:\WINDOWS\System32\dllhost.exe /Processid:{12345678-1234-1234-1234-123456789012}",
        r"wscript.exe C:\App\x.vbs",
        // The interpreter itself inside the app's root: still a host.
        r"C:\Program Files\App\python.exe C:\Program Files\App\svc.py",
        r#""C:\Program Files\App\jre\bin\javaw.exe" -jar app.jar"#,
        r#""C:\Program Files\App\pwsh.exe" -File x.ps1"#,
    ] {
        assert_eq!(resolve_program(raw, &env), unresolved(raw), "{raw}");
        assert_eq!(one_service("S", raw, 16).program, unresolved(raw), "{raw}");
    }
    // The same rule for plain paths (a task's exec path, a firewall rule's App=).
    for raw in [
        r"C:\Program Files\App\node.exe",
        r#""%SystemRoot%\System32\cmd.exe""#,
        r"C:\WINDOWS\System32\conhost.exe",
    ] {
        assert_eq!(resolve_file(raw, &env), unresolved(raw), "{raw}");
    }
}

#[test]
fn svc_driver_and_peruser_flags() {
    let index = index();
    assert!(service(&index, "appdrv").is_driver);
    for ty in [1, 2, 8, 0x0a] {
        assert!(one_service("d", r"\SystemRoot\x.sys", ty).is_driver, "{ty}");
    }
    for ty in [0x10, 0x20, 0x50, 0x110] {
        assert!(!one_service("d", r"C:\App\x.exe", ty).is_driver, "{ty}");
    }

    // Template (Type 0x60) and instance (name `<stem>_<hex>`, whatever its Type).
    assert!(service(&index, "CDPUserSvc").per_user_template);
    assert!(service(&index, "CDPUserSvc_4a5b1").per_user_template);
    assert!(!service(&index, "AppSvc").per_user_template);
    assert!(one_service("X", r"C:\App\x.exe", 0x50).per_user_template);
    assert!(one_service("X", r"C:\App\x.exe", 0xe0).per_user_template);
    // `_<hex>` without a service of the stem's name is not an instance.
    assert!(!one_service("Foo_1a2b", r"C:\App\x.exe", 0x10).per_user_template);

    let fx = Fixture::builder()
        .dword(&format!(r"{SVC}\Foo"), "Type", 0x10)
        .dword(&format!(r"{SVC}\foo_1A2B"), "Type", 0x10)
        .dword(&format!(r"{SVC}\Foo_zz"), "Type", 0x10)
        .dword(&format!(r"{SVC}\Foo_"), "Type", 0x10)
        .build();
    let mut errors = Vec::new();
    let services = read_services(&fx, &env(), &mut errors).unwrap();
    let flag = |n: &str| {
        services
            .iter()
            .find(|s| s.identity.name == n)
            .unwrap()
            .per_user_template
    };
    assert!(flag("foo_1A2B"));
    assert!(!flag("Foo") && !flag("Foo_zz") && !flag("Foo_"));
}

#[test]
fn svc_dependents_case_insensitive_group_entries_ignored() {
    let index = index();
    assert_eq!(service(&index, "AppSvc").depend_on, ["RpcSs"]);
    assert_eq!(index.dependents_of("APPSVC"), ["AppHelper"]);
    assert_eq!(index.dependents_of("appsvc"), ["AppHelper"]);
    assert_eq!(index.dependents_of("rpcss"), ["AppSvc"]);
    assert_eq!(index.dependents_of("NSI"), ["Dnscache"]);
    assert!(index.dependents_of("NetworkProvider").is_empty());
    assert!(index.dependents_of("+NetworkProvider").is_empty());
    assert!(index.dependents_of("AppHelper").is_empty());

    // A REG_SZ DependOnService is one entry; any other type leaves the service out (counted).
    let fx = Fixture::builder()
        .sz(&format!(r"{SVC}\A"), "DependOnService", "Base")
        .dword(&format!(r"{SVC}\B"), "DependOnService", 1)
        .build();
    let mut errors = Vec::new();
    let services = read_services(&fx, &env(), &mut errors).unwrap();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].depend_on, ["Base"]);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("service B"), "{errors:?}");
}

#[test]
fn svc_delete_flag_read() {
    let index = index();
    assert!(service(&index, "Gone").delete_flag);
    assert!(!service(&index, "AppSvc").delete_flag);
    let key = format!(r"{SVC}\Z");
    let fx = Fixture::builder().dword(&key, "DeleteFlag", 0).build();
    let mut errors = Vec::new();
    assert!(!read_services(&fx, &env(), &mut errors).unwrap()[0].delete_flag);
}

/// Only the control set the source reports as current is read; the `CurrentControlSet` spelling is
/// mapped to it by the source.
#[test]
fn svc_reads_the_current_control_set_only() {
    let fx = Fixture::builder()
        .dword(r"HKLM\SYSTEM\ControlSet001\Services\Old", "Type", 16)
        .dword(r"HKLM\SYSTEM\ControlSet002\Services\New", "Type", 16)
        .sz(
            r"HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
            "old",
            "v2.33|Action=Allow|Name=Old|",
        )
        .sz(
            r"HKLM\SYSTEM\ControlSet002\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
            "new",
            "v2.33|Action=Allow|Name=New|",
        )
        .with(|f| f.set_current_control_set(2))
        .build();
    let index = sysobj::build(&fx, &fx);
    let names: Vec<&str> = index
        .services
        .iter()
        .map(|s| s.identity.name.as_str())
        .collect();
    assert_eq!(names, ["New", "SharedAccess"]);
    assert_eq!(index.firewall.len(), 1);
    assert_eq!(index.firewall[0].identity.id, "new");
    assert!(SERVICES_KEY.contains("CurrentControlSet"));
    assert!(FIREWALL_RULES_KEY.starts_with(SERVICES_KEY));
}

// ---------------------------------------------------------------------------------------------------------
// Firewall rules
// ---------------------------------------------------------------------------------------------------------

#[test]
fn fw_reads_all_values_bad_value_counted() {
    let index = index();
    assert_eq!(index.firewall.len(), 8);
    let fw_errors: Vec<&String> = index
        .errors
        .iter()
        .filter(|e| e.contains("firewall rule"))
        .collect();
    assert_eq!(fw_errors.len(), 3, "{:?}", index.errors);
    for n in ["5", "6", "7"] {
        let id = format!("{{22222222-0000-0000-0000-00000000000{n}}}");
        assert!(index.firewall.iter().all(|r| r.identity.id != id), "{id}");
        assert!(fw_errors.iter().any(|e| e.contains(&id)), "{id}");
    }
    // The identity is the value name and the string byte for byte.
    let f1 = rule(&index, "1111-0000-0000-0000-000000000001}");
    assert_eq!(f1.identity.id, "{11111111-0000-0000-0000-000000000001}");
    assert_eq!(
        f1.identity.rule,
        r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=C:\Program Files\PurgeSpike\app1.exe|Name=PurgeSpike F1 program|Defer=User|"
    );
    assert_eq!(f1.fields.get("Defer"), Some("User"));
    assert_eq!(f1.program, file(r"C:\Program Files\PurgeSpike\app1.exe"));
    // A rule bound to a service through svchost: the program is a host, the service is named.
    let f4 = rule(&index, "1111-0000-0000-0000-000000000004}");
    assert_eq!(f4.service.as_deref(), Some("PurgeSpikeS1"));
    assert_eq!(f4.program, unresolved(r"%SystemRoot%\System32\svchost.exe"));
    assert!(
        index.errors.iter().all(|e| !e.contains("service")),
        "{:?}",
        index.errors
    );
}

#[test]
fn fw_app_env_expanded() {
    let index = index();
    let app = rule(&index, "2222-0000-0000-0000-000000000001}");
    assert_eq!(app.program, file(r"C:\Program Files\App\app.exe"));
    assert_eq!(app.fields.get("App"), Some(r"%ProgramFiles%\App\app.exe"));
    assert!(app.identity.rule.contains("%ProgramFiles%"));

    let out = rules(&[
        ("q", r#"v2.33|App="%ProgramFiles%\App\a b.exe"|Name=Q|"#),
        ("u", r"v2.33|App=%NOPE%\a.exe|Name=U|"),
        ("two", r"v2.33|App=C:\A\a.exe|App=C:\B\b.exe|Name=T|"),
        ("svc2", r"v2.33|App=C:\A\a.exe|Svc=x|Svc=y|Name=S|"),
    ]);
    let by = |id: &str| out.iter().find(|r| r.identity.id == id).unwrap();
    assert_eq!(by("q").program, file(r"C:\Program Files\App\a b.exe"));
    assert_eq!(by("u").program, unresolved(r"%NOPE%\a.exe"));
    assert!(matches!(by("two").program, ProgramRef::Unresolved { .. }));
    assert!(matches!(by("svc2").program, ProgramRef::Unresolved { .. }));
    assert_eq!(by("svc2").service.as_deref(), Some("x"));
}

#[test]
fn fw_app_system_is_none() {
    let index = index();
    assert_eq!(
        rule(&index, "2222-0000-0000-0000-000000000003}").program,
        ProgramRef::None
    );
    // No App= at all.
    assert_eq!(
        rule(&index, "1111-0000-0000-0000-000000000002}").program,
        ProgramRef::None
    );
    let out = rules(&[
        ("sys", "v2.33|App=SYSTEM|Name=A|"),
        ("empty", "v2.33|App=|Name=B|"),
        ("blank", "v2.33|App= |Name=C|"),
    ]);
    assert!(out.iter().all(|r| r.program == ProgramRef::None), "{out:?}");
}

#[test]
fn fw_package_bound_detected() {
    let out = rules(&[
        ("pkg", "v2.33|Action=Allow|AppPkgId=S-1-15-2-1-2-3|Name=A|"),
        (
            "pfn",
            "v2.33|Action=Allow|PFN=Microsoft.App_8wekyb3d8bbwe|Name=B|",
        ),
        (
            "luown",
            "v2.33|Action=Allow|LUOwn=S-1-5-21-1-2-3-1001|Name=C|",
        ),
        ("lower", "v2.33|Action=Allow|apppkgid=x|Name=D|"),
        ("sid", "v2.33|Action=Allow|LUAuth=s-1-15-3-1024-1|Name=E|"),
        ("plain", r"v2.33|Action=Allow|App=C:\A\a.exe|Name=F|"),
    ]);
    for r in &out {
        assert_eq!(
            r.package_bound,
            r.identity.id != "plain",
            "{}",
            r.identity.id
        );
    }
    assert!(rule(&index(), "2222-0000-0000-0000-000000000004}").package_bound);
}

#[test]
fn fw_resource_name_detected() {
    let index = index();
    assert!(rule(&index, "2222-0000-0000-0000-000000000003}").resource_name);
    assert!(!rule(&index, "2222-0000-0000-0000-000000000001}").resource_name);
    let out = rules(&[(
        "r",
        "v2.33|Name=@{Microsoft.App_1.0_x64__8wekyb3d8bbwe?ms-resource://x}|",
    )]);
    assert!(out[0].resource_name);
}

#[test]
fn fw_rules_named_returns_all_with_same_display_name() {
    let index = index();
    let named = index.rules_named("App In");
    let ids: Vec<&str> = named.iter().map(|r| r.identity.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "{22222222-0000-0000-0000-000000000001}",
            "{22222222-0000-0000-0000-000000000002}"
        ]
    );
    assert_eq!(index.rules_named("PurgeSpike F6 group").len(), 1);
    assert!(index.rules_named("App").is_empty());
}

// ---------------------------------------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------------------------------------

fn exec(path: &str) -> TaskAction {
    TaskAction::Exec {
        path: path.to_owned(),
        arguments: Some(r"C:\Other\x.exe".to_owned()),
        working_dir: None,
    }
}

fn com() -> TaskAction {
    TaskAction::ComHandler {
        clsid: "{01234567-89AB-CDEF-0123-456789ABCDEF}".to_owned(),
        data: None,
    }
}

fn task(actions: Vec<TaskAction>) -> TaskIdentity {
    TaskIdentity {
        path: r"\App\T".to_owned(),
        actions,
    }
}

#[test]
fn task_multi_action_all_must_resolve() {
    let env = env();
    let both = task_programs(
        &task(vec![
            exec(r"C:\Program Files\App\a.exe"),
            exec(r#""%ProgramFiles%\App\b.exe""#),
            exec(r"C:\Program Files\App\a.exe"),
        ]),
        &env,
    );
    assert_eq!(
        both.files(),
        Some(vec![
            r"C:\Program Files\App\a.exe",
            r"C:\Program Files\App\b.exe"
        ])
    );
    // One exec action that is not one file (a host here) and nothing is attributed.
    for second in [
        r"%SystemRoot%\System32\cmd.exe",
        r"relative\b.exe",
        "",
        r#""C:\Program Files\App\b.exe" /x"#,
    ] {
        let t = task_programs(
            &task(vec![exec(r"C:\Program Files\App\a.exe"), exec(second)]),
            &env,
        );
        assert_eq!(t.files(), None, "{second:?}");
        assert!(matches!(t.actions[1], ProgramRef::Unresolved { .. }));
    }
    // Arguments are ignored for attribution.
    let one = task_programs(&task(vec![exec(r"C:\Program Files\App\a.exe")]), &env);
    assert_eq!(one.files(), Some(vec![r"C:\Program Files\App\a.exe"]));
    // An action of another kind is not a known program.
    let other = task_programs(
        &task(vec![
            exec(r"C:\Program Files\App\a.exe"),
            TaskAction::Other {
                kind: "send_email".to_owned(),
            },
        ]),
        &env,
    );
    assert_eq!(other.files(), None);
    // A task the user cannot read has no actions and no files.
    assert_eq!(task_programs(&task(Vec::new()), &env).files(), None);

    let index = index();
    let update = &index.tasks[0].identity;
    assert_eq!(
        task_programs(update, &env).files(),
        Some(vec![r"C:\Program Files\App\update.exe"])
    );
}

#[test]
fn task_com_handler_is_none() {
    let env = env();
    let t = task_programs(&task(vec![com()]), &env);
    assert_eq!(t.actions, [ProgramRef::None]);
    assert_eq!(t.files(), None);
    // Next to an exec action, the COM handler is the caller's to resolve; the exec files stand.
    let mixed = task_programs(
        &task(vec![com(), exec(r"C:\Program Files\App\a.exe")]),
        &env,
    );
    assert_eq!(mixed.actions[0], ProgramRef::None);
    assert_eq!(mixed.files(), Some(vec![r"C:\Program Files\App\a.exe"]));

    let index = index();
    let handler = &index.tasks[1].identity;
    assert_eq!(task_programs(handler, &env).actions, [ProgramRef::None]);
}

// ---------------------------------------------------------------------------------------------------------
// build
// ---------------------------------------------------------------------------------------------------------

#[test]
fn build_degrades_on_not_captured() {
    // Registry captured only under SOFTWARE, no tasks section: every list is unknown.
    let fx = Fixture::builder()
        .sz(r"HKLM\SOFTWARE\X", "a", "b")
        .with(|f| {
            f.set_registry_coverage(Coverage {
                roots: vec![CoverageRoot {
                    path: r"HKLM\SOFTWARE".to_owned(),
                    depth: None,
                }],
                exclude: Vec::new(),
            })
        })
        .build();
    let index = sysobj::build(&fx, &fx);
    assert!(index.services.is_empty() && index.firewall.is_empty() && index.tasks.is_empty());
    assert_eq!(index.errors.len(), 3, "{:?}", index.errors);
    assert!(
        index.errors.iter().all(|e| e.contains("not captured")),
        "{:?}",
        index.errors
    );

    // Access denied on the lists: the same; on one service key: that service is skipped and counted.
    let denied = |path: &'static str| {
        move |f: &mut Fixture| {
            f.add_denied(path);
        }
    };
    let base = || -> FixtureBuilder {
        Fixture::builder()
            .dword(&format!(r"{SVC}\A"), "Type", 16)
            .dword(&format!(r"{SVC}\B"), "Type", 16)
            .sz(FW, "r", "v2.33|Name=R|")
            .task(TaskInfo::default())
    };
    let fx = base()
        .with(denied(r"HKLM\SYSTEM\ControlSet001\Services"))
        .build();
    let index = sysobj::build(&fx, &fx);
    assert!(index.services.is_empty() && index.firewall.is_empty());
    assert_eq!(index.tasks.len(), 1);
    assert_eq!(index.errors.len(), 2, "{:?}", index.errors);

    let fx = base()
        .with(denied(r"HKLM\SYSTEM\ControlSet001\Services\B"))
        .build();
    let index = sysobj::build(&fx, &fx);
    let names: Vec<&str> = index
        .services
        .iter()
        .map(|s| s.identity.name.as_str())
        .collect();
    assert_eq!(names, ["A", "SharedAccess"]);
    assert_eq!(index.firewall.len(), 1);
    assert_eq!(index.errors.len(), 1, "{:?}", index.errors);
    assert!(index.errors[0].contains("service B"));

    let fx = base()
        .with(denied(r"HKLM\SYSTEM\ControlSet001\Services\A\Parameters"))
        .build();
    let index = sysobj::build(&fx, &fx);
    assert_eq!(index.services.len(), 2, "{:?}", index.services);
    assert!(index.errors[0].contains(r"service A: Parameters\ServiceDll"));

    // The full machine reads without an error other than the three bad firewall values.
    assert_eq!(super_index_errors(), 3);
}

fn super_index_errors() -> usize {
    index().errors.len()
}

/// A registry source that records every call it passes on.
struct Counting<'a> {
    inner: &'a Fixture,
    calls: Mutex<Vec<(&'static str, String)>>,
}

impl Counting<'_> {
    fn log(&self, op: &'static str, key: &str) {
        self.calls.lock().unwrap().push((op, key.to_owned()));
    }
}

impl RegistrySource for Counting<'_> {
    fn key_info(&self, key: &str) -> SourceResult<KeyInfo> {
        self.log("key_info", key);
        self.inner.key_info(key)
    }
    fn subkeys(&self, key: &str) -> SourceResult<Vec<String>> {
        self.log("subkeys", key);
        self.inner.subkeys(key)
    }
    fn values(&self, key: &str) -> SourceResult<Vec<RegValue>> {
        self.log("values", key);
        self.inner.values(key)
    }
    fn value(&self, key: &str, name: &str) -> SourceResult<RegData> {
        self.log("value", key);
        self.inner.value(key, name)
    }
    fn loaded_user_sids(&self) -> SourceResult<Vec<String>> {
        self.log("loaded_user_sids", "");
        self.inner.loaded_user_sids()
    }
    fn current_control_set(&self) -> SourceResult<u32> {
        self.log("current_control_set", "");
        self.inner.current_control_set()
    }
}

#[test]
fn budget_service_reads() {
    let fx = machine();
    let counting = Counting {
        inner: &fx,
        calls: Mutex::new(Vec::new()),
    };
    let mut errors = Vec::new();
    let services = read_services(&counting, &env(), &mut errors).unwrap();
    let n = services.len();
    assert_eq!(n, 9, "{errors:?}");
    let calls = counting.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1 + 2 * n, "{calls:?}");
    assert_eq!(calls[0], ("subkeys", SERVICES_KEY.to_owned()));
    let count = |op: &str| calls.iter().filter(|(o, _)| *o == op).count();
    assert_eq!((count("values"), count("value")), (n, n));
    for (op, key) in &calls[1..] {
        let rest = key
            .strip_prefix(SERVICES_KEY)
            .and_then(|r| r.strip_prefix('\\'))
            .unwrap_or_else(|| panic!("{op} outside Services: {key}"));
        let depth = rest.split('\\').count();
        match *op {
            "values" => assert_eq!(depth, 1, "{key}"),
            "value" => assert!(depth == 2 && rest.ends_with(r"\Parameters"), "{key}"),
            _ => panic!("unexpected {op} {key}"),
        }
    }

    // The firewall reader: one values call.
    counting.calls.lock().unwrap().clear();
    read_firewall(&counting, &env(), &mut errors).unwrap();
    let calls = counting.calls.lock().unwrap().clone();
    assert_eq!(calls, [("values", FIREWALL_RULES_KEY.to_owned())]);
}
