//! Service Control Manager wrapper tests.
//!
//! Tests without `#[ignore]` only read: they query a missing name and existing built-in services, check
//! argument refusals that return before any SCM call, and grep the crate's sources.
//!
//! The `#[ignore]`d tests create, configure and delete services named `PurgeTestSvc_<pid>_<tag>` whose
//! binary does not exist; they are never started. They need an elevated administrator and run only in the
//! VM rig (m1b-x-elevated: `<test exe> --ignored --exact <name>`). Unelevated they print a SKIPPED line and
//! return without asserting anything.

use purge_win::scm::{WinError, query};

#[cfg(feature = "write")]
use purge_win::scm::{
    Config2Item, Config2Kind, FailureAction, FailureActions, ScmCreate, ScmDelete, ScmGuid,
    ScmTrigger, TriggerDataItem, create, delete, set_config2, set_security,
};

/// The crate's sources, as (file name, text).
fn crate_sources() -> Vec<(String, String)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&p).unwrap();
                out.push((p.display().to_string(), text));
            }
        }
    }
    assert!(out.iter().any(|(n, _)| n.ends_with("scm.rs")));
    out
}

/// No source file of purge-win names an API that changes a service's run state, sends it a control,
/// changes its main configuration or waits on its status (C-WIN).
#[test]
fn no_control_or_start_symbols() {
    let forbidden = [
        "ControlService",
        "StartService",
        "ChangeServiceConfigW",
        "ChangeServiceConfigA",
        "NotifyServiceStatusChange",
    ];
    for (file, text) in crate_sources() {
        for f in forbidden {
            assert!(!text.contains(f), "{file} mentions {f}");
        }
    }
}

#[test]
fn query_missing_service_is_none() {
    let name = format!("PurgeNoSuchService_{}", std::process::id());
    assert_eq!(query(&name), Ok(None));
}

#[test]
fn query_rejects_invalid_names_before_any_call() {
    for bad in ["", "a\\b", "a/b", "a\0b"] {
        assert!(
            matches!(query(bad), Err(WinError::InvalidName(_))),
            "{bad:?}"
        );
    }
}

/// Read-only query of built-in services on the host: whatever the token, a service that answers has a
/// configuration, a status and an owner/group/DACL SDDL; an unelevated token may be refused READ_CONTROL
/// on some, which is an access-denied error and never a wrong `None`.
#[test]
fn query_existing_services_read_only() {
    let mut answered = 0;
    for name in ["RpcSs", "EventLog", "Schedule", "Winmgmt"] {
        match query(name) {
            Ok(Some(s)) => {
                answered += 1;
                assert_eq!(s.name, name);
                assert!(!s.config.binary_path.is_empty(), "{name}");
                assert!(
                    !s.config.binary_path.contains("%SystemRoot%"),
                    "{name}: the SCM expands ImagePath ({})",
                    s.config.binary_path
                );
                assert!(
                    s.sddl.starts_with("O:") && s.sddl.contains("D:"),
                    "{name}: {}",
                    s.sddl
                );
                assert!(
                    s.config2.triggers.is_some(),
                    "{name}: trigger level supported"
                );
                assert!(s.config2.failure_actions.is_some(), "{name}");
                assert!(s.status.current_state >= 1 && s.status.current_state <= 7);
                // Split svchost services report 0x30 here; delete must not mistake them for drivers.
                assert!(
                    purge_win::scm::is_plain_win32_service(s.status.service_type),
                    "{name}: {:#x}",
                    s.status.service_type
                );
            }
            Ok(None) => panic!("built-in service {name} not found"),
            Err(e) => assert!(e.is_access_denied(), "{name}: {e}"),
        }
    }
    assert!(answered > 0, "no built-in service could be queried");
}

#[cfg(feature = "write")]
#[test]
fn mutating_calls_reject_invalid_names_before_any_call() {
    for bad in ["", "a\\b", "a/b"] {
        assert!(matches!(delete(bad), Err(WinError::InvalidName(_))));
        assert!(matches!(
            set_config2(bad, Config2Item::PreshutdownTimeout(1)),
            Err(WinError::InvalidName(_))
        ));
        assert!(matches!(
            set_security(bad, "D:(A;;GA;;;SY)"),
            Err(WinError::InvalidName(_))
        ));
    }
}

/// Hostile: a forged definition for a kernel driver is refused before the SCM is opened, so this test
/// creates nothing even when run elevated.
#[cfg(feature = "write")]
#[test]
fn create_refuses_driver_definition_before_any_call() {
    let def = ScmCreate {
        name: format!("PurgeNeverCreated_{}", std::process::id()),
        display_name: None,
        service_type: 0x1,
        start_type: 3,
        error_control: 1,
        binary_path: r"C:\Windows\System32\drivers\null.sys".into(),
        load_order_group: None,
        dependencies: vec![],
        service_start_name: None,
    };
    assert!(matches!(create(&def), Err(WinError::Refused(_))));
    assert_eq!(query(&def.name), Ok(None));
}

// ---------------------------------------------------------------------------------------------
// Elevated tests (VM rig only)
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "write")]
mod elevated {
    use super::*;

    /// True when the process is elevated; otherwise prints the reason the test is skipped.
    fn elevated_or_skip(test: &str) -> bool {
        match purge_win::sid::is_elevated() {
            Ok(true) => true,
            other => {
                println!(
                    "SKIPPED {test}: needs an elevated administrator (VM rig m1b-x-elevated); \
                     elevation check: {other:?}"
                );
                false
            }
        }
    }

    /// A test service that is deleted when the guard drops (pass or fail). Never started.
    struct TestSvc {
        name: String,
    }

    impl TestSvc {
        fn create(tag: &str, edit: impl FnOnce(&mut ScmCreate)) -> (TestSvc, ScmCreate) {
            let name = format!("PurgeTestSvc_{}_{tag}", std::process::id());
            assert_eq!(query(&name), Ok(None), "{name} exists before the test");
            let mut def = ScmCreate {
                name: name.clone(),
                display_name: Some(format!("Purge test {tag}")),
                service_type: 0x10,
                start_type: 3,
                error_control: 1,
                binary_path: format!(r#""C:\PurgeTestMissing\{tag}\svc.exe" -run"#),
                load_order_group: None,
                dependencies: vec!["RpcSs".into()],
                service_start_name: Some(r"NT AUTHORITY\LocalService".into()),
            };
            edit(&mut def);
            create(&def).unwrap();
            (TestSvc { name }, def)
        }
    }

    impl Drop for TestSvc {
        fn drop(&mut self) {
            match delete(&self.name) {
                Ok(_) | Err(WinError::NotFound) => {}
                Err(e) => eprintln!("cleanup of {} failed: {e}", self.name),
            }
        }
    }

    fn all_items() -> Vec<Config2Item> {
        vec![
            Config2Item::Description("Purge SCM wrapper test service".into()),
            Config2Item::FailureActions(FailureActions {
                reset_period: 86_400,
                reboot_msg: None,
                command: Some(r#""C:\PurgeTestMissing\notify.exe" failed"#.into()),
                actions: vec![
                    FailureAction {
                        action_type: 1,
                        delay_ms: 60_000,
                    },
                    FailureAction {
                        action_type: 3,
                        delay_ms: 120_000,
                    },
                    FailureAction {
                        action_type: 0,
                        delay_ms: 0,
                    },
                ],
            }),
            Config2Item::FailureActionsFlag(true),
            Config2Item::DelayedAutoStart(true),
            Config2Item::ServiceSidType(1),
            Config2Item::RequiredPrivileges(vec![
                "SeChangeNotifyPrivilege".into(),
                "SeCreateGlobalPrivilege".into(),
            ]),
            Config2Item::PreshutdownTimeout(30_000),
            Config2Item::Triggers(vec![
                ScmTrigger {
                    trigger_type: 2,
                    action: 1,
                    // NETWORK_MANAGER_FIRST_IP_ADDRESS_ARRIVAL_GUID (sc triggerinfo start/networkon).
                    subtype: ScmGuid::parse("{4f27f2de-14e2-430b-a549-7cd48cbc8245}"),
                    data: vec![],
                },
                ScmTrigger {
                    trigger_type: 20,
                    action: 1,
                    subtype: ScmGuid::parse("{6e3b8b3b-1e6c-4d8a-9c5e-1b2f3a4d5e6f}"),
                    data: vec![TriggerDataItem {
                        data_type: 2,
                        bytes: "hello\0"
                            .encode_utf16()
                            .flat_map(u16::to_le_bytes)
                            .collect(),
                    }],
                },
            ]),
        ]
    }

    fn value_of(c2: &purge_win::scm::ScmConfig2, kind: Config2Kind) -> Option<Config2Item> {
        c2.items().into_iter().find(|i| i.kind() == kind)
    }

    #[test]
    #[ignore = "creates, configures and deletes a test service; elevated, VM rig only (m1b-x-elevated)"]
    fn create_then_query_equals_definition() {
        if !elevated_or_skip("create_then_query_equals_definition") {
            return;
        }
        let (svc, def) = TestSvc::create("cq", |_| {});
        let s = query(&svc.name).unwrap().expect("created service");
        assert_eq!(s.config.service_type, def.service_type);
        assert_eq!(s.config.start_type, def.start_type);
        assert_eq!(s.config.error_control, def.error_control);
        assert_eq!(s.config.binary_path, def.binary_path);
        assert_eq!(s.config.load_order_group, def.load_order_group);
        assert_eq!(s.config.dependencies, def.dependencies);
        assert_eq!(s.config.service_start_name, def.service_start_name);
        assert_eq!(s.config.display_name, def.display_name);
        assert!(s.status.is_stopped(), "never started");
        assert_eq!(delete(&svc.name), Ok(ScmDelete::Deleted));
        assert_eq!(query(&svc.name), Ok(None));

        // An expandable path is stored raw and returned expanded (spike query_config_expands_image_path).
        let (svc, _) = TestSvc::create("cqx", |d| {
            d.binary_path = r"%SystemRoot%\PurgeTestMissing\svc.exe".into();
        });
        let s = query(&svc.name).unwrap().expect("created service");
        assert!(
            !s.config.binary_path.contains('%')
                && s.config
                    .binary_path
                    .to_ascii_lowercase()
                    .ends_with(r"\purgetestmissing\svc.exe"),
            "{}",
            s.config.binary_path
        );
    }

    #[test]
    #[ignore = "creates and deletes a test service; elevated, VM rig only (m1b-x-elevated)"]
    fn create_exists_is_distinct_error() {
        if !elevated_or_skip("create_exists_is_distinct_error") {
            return;
        }
        let (svc, def) = TestSvc::create("ex", |_| {});
        assert_eq!(create(&def), Err(WinError::Exists));
        // The same display name under another service name is never `Exists`. Build 26100 creates it
        // (docs/reviews/m1b/vm-objects-run.md); `DuplicateName` is allowed where Windows still refuses
        // it. No executor path depends on that error (review R3b).
        let other = ScmCreate {
            name: format!("{}_2", svc.name),
            ..def.clone()
        };
        let r = create(&other);
        if r.is_ok() {
            assert_eq!(delete(&other.name).map(|_| ()), Ok(()));
        }
        assert!(matches!(r, Ok(()) | Err(WinError::DuplicateName)), "{r:?}");
        assert_eq!(query(&other.name), Ok(None));
    }

    #[test]
    #[ignore = "creates and deletes a test service while holding a second handle; elevated, VM rig only (m1b-x-elevated)"]
    fn delete_marked_for_delete_reported() {
        use windows_sys::Win32::System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT,
            SERVICE_QUERY_STATUS,
        };
        if !elevated_or_skip("delete_marked_for_delete_reported") {
            return;
        }
        let (svc, def) = TestSvc::create("mk", |_| {});
        let wname: Vec<u16> = svc.name.encode_utf16().chain([0]).collect();
        /// Closes a raw SCM handle on drop (also on a failed assert, before `svc` deletes the service).
        struct H(windows_sys::Win32::System::Services::SC_HANDLE);
        impl Drop for H {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: handle owned by this guard.
                    unsafe { CloseServiceHandle(self.0) };
                }
            }
        }
        // SAFETY: local manager, null machine and database names.
        let mgr =
            H(unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) });
        assert!(!mgr.0.is_null());
        // SAFETY: live manager handle, NUL-terminated name.
        let second = H(unsafe { OpenServiceW(mgr.0, wname.as_ptr(), SERVICE_QUERY_STATUS) });
        assert!(!second.0.is_null());

        assert_eq!(delete(&svc.name), Ok(ScmDelete::Marked));
        // Still there while marked; a second delete and a create both see the mark.
        assert!(query(&svc.name).unwrap().is_some());
        assert_eq!(delete(&svc.name), Ok(ScmDelete::Marked));
        assert_eq!(create(&def), Err(WinError::MarkedForDelete));

        drop(second);
        assert_eq!(
            query(&svc.name),
            Ok(None),
            "gone after the last handle closed"
        );
        assert_eq!(delete(&svc.name), Err(WinError::NotFound));
        // The name is free again.
        create(&def).unwrap();
        assert_eq!(delete(&svc.name), Ok(ScmDelete::Deleted));
    }

    #[test]
    #[ignore = "creates, configures and deletes a test service; elevated, VM rig only (m1b-x-elevated)"]
    fn set_config2_each_item_round_trips() {
        if !elevated_or_skip("set_config2_each_item_round_trips") {
            return;
        }
        // Auto start: delayed auto-start is only accepted for auto-start services. Never started.
        let (svc, _) = TestSvc::create("c2", |d| d.start_type = 2);
        for item in all_items() {
            let kind = item.kind();
            set_config2(&svc.name, item.clone()).unwrap_or_else(|e| panic!("{kind:?}: {e}"));
            let s = query(&svc.name).unwrap().expect("service");
            assert_eq!(value_of(&s.config2, kind), Some(item), "{kind:?}");
        }
        // The two values the SCM refuses are refused before it is called.
        for item in [
            Config2Item::Triggers(vec![]),
            Config2Item::LaunchProtected(0),
        ] {
            assert!(matches!(
                set_config2(&svc.name, item),
                Err(WinError::NotSettable { .. })
            ));
        }
    }

    #[test]
    #[ignore = "creates, changes the DACL of and deletes a test service; elevated, VM rig only (m1b-x-elevated)"]
    fn set_security_round_trips_sddl() {
        if !elevated_or_skip("set_security_round_trips_sddl") {
            return;
        }
        let (svc, _) = TestSvc::create("sd", |_| {});
        let before = query(&svc.name).unwrap().expect("service").sddl;
        let wanted = format!("{before}(A;;RPWPCR;;;AU)");
        set_security(&svc.name, &wanted).unwrap();
        let after = query(&svc.name).unwrap().expect("service").sddl;
        assert_eq!(after, wanted);
        // Owner and group are untouched (only the DACL is set).
        assert_eq!(after.split("D:").next(), before.split("D:").next());
        // Back to the original.
        set_security(&svc.name, &before).unwrap();
        assert_eq!(query(&svc.name).unwrap().expect("service").sddl, before);
        // A NULL DACL is refused and changes nothing.
        assert!(matches!(
            set_security(&svc.name, "D:NO_ACCESS_CONTROL"),
            Err(WinError::InvalidArgument(_))
        ));
        assert_eq!(query(&svc.name).unwrap().expect("service").sddl, before);
    }

    #[test]
    #[ignore = "creates, configures and deletes a test service; elevated, VM rig only (m1b-x-elevated)"]
    fn query_own_test_service_round_trips_all_fields() {
        if !elevated_or_skip("query_own_test_service_round_trips_all_fields") {
            return;
        }
        let (svc, def) = TestSvc::create("rt", |d| {
            d.start_type = 2;
            d.dependencies = vec!["RpcSs".into(), "+NetworkProvider".into()];
        });
        for item in all_items() {
            set_config2(&svc.name, item).unwrap();
        }
        let base = query(&svc.name).unwrap().expect("service").sddl;
        let sddl = format!("{base}(A;;RPWPCR;;;AU)");
        set_security(&svc.name, &sddl).unwrap();

        let s = query(&svc.name).unwrap().expect("service");
        assert_eq!(s.name, svc.name);
        assert_eq!(s.config.service_type, def.service_type);
        assert_eq!(s.config.start_type, def.start_type);
        assert_eq!(s.config.error_control, def.error_control);
        assert_eq!(s.config.binary_path, def.binary_path);
        assert_eq!(s.config.load_order_group, None);
        assert_eq!(s.config.tag_id, 0);
        assert_eq!(s.config.dependencies, def.dependencies);
        assert_eq!(s.config.service_start_name, def.service_start_name);
        assert_eq!(s.config.display_name, def.display_name);
        for item in all_items() {
            assert_eq!(
                value_of(&s.config2, item.kind()),
                Some(item.clone()),
                "{item:?}"
            );
        }
        assert_eq!(s.config2.launch_protected, Some(0));
        assert_eq!(s.sddl, sddl);
        assert!(
            s.status.is_stopped() && s.status.process_id == 0,
            "never started"
        );

        assert_eq!(delete(&svc.name), Ok(ScmDelete::Deleted));
        assert_eq!(query(&svc.name), Ok(None));
    }
}
