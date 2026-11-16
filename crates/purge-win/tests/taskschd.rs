//! Task Scheduler wrapper tests.
//!
//! Tests that register tasks do so only under a folder `\PurgeTest-<random>\` of their own and remove
//! every task and folder below it afterwards, also when they fail ([`TestFolder`]). The tasks they
//! register are disabled, have no trigger and refuse to start on demand, so nothing ever runs. They need
//! no elevation (a standard user may create folders and tasks under `\`); in the VM they run elevated
//! as part of `m1b-x-elevated`. Listing reads the whole host tree and changes nothing.
#![cfg(all(feature = "read", feature = "com"))]
// Without `write` only the read-only tests run; the registration helpers are then unused.
#![cfg_attr(not(feature = "write"), allow(dead_code, unused_imports))]

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU32, Ordering};

use purge_win::taskschd::{self, ListLimits, LogonType, RawAction, WinError};

/// The exec action of every test task. The file does not exist; the task never runs anyway.
const EXEC_PATH: &str = r"C:\PurgeTest\does-not-exist.exe";
const COM_CLSID: &str = "{0F3C6D2A-5B1E-4C7D-9A8B-2E4F6A1C3D5E}";

/// A disabled task with no trigger that cannot be started on demand.
fn task_xml(description: &str, hidden: bool, com_handler: bool) -> String {
    let com = if com_handler {
        format!("<ComHandler><ClassId>{COM_CLSID}</ClassId><Data>purge-data</Data></ComHandler>")
    } else {
        String::new()
    };
    format!(
        r#"<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>PurgeTest</Author><Description>{description}</Description></RegistrationInfo>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><Enabled>false</Enabled><AllowStartOnDemand>false</AllowStartOnDemand><Hidden>{hidden}</Hidden></Settings>
  <Actions Context="Author"><Exec><Command>{EXEC_PATH}</Command><Arguments>--never</Arguments><WorkingDirectory>C:\PurgeTest</WorkingDirectory></Exec>{com}</Actions>
</Task>"#
    )
}

/// A fresh `\PurgeTest-<random>` folder name (the folder itself is created by the first registration).
fn random_name() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    let mut h = RandomState::new().build_hasher();
    h.write_u32(std::process::id());
    h.write_u32(N.fetch_add(1, Ordering::Relaxed));
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    format!("PurgeTest-{:016x}", h.finish())
}

/// Owns `\PurgeTest-<random>`: removes every task and folder below it, and itself, on drop.
struct TestFolder {
    name: String,
}

impl TestFolder {
    fn new() -> TestFolder {
        TestFolder {
            name: random_name(),
        }
    }

    /// `\PurgeTest-<random>\<rel>`.
    fn path(&self, rel: &str) -> String {
        format!("\\{}\\{rel}", self.name)
    }
}

impl Drop for TestFolder {
    fn drop(&mut self) {
        assert!(self.name.starts_with("PurgeTest-"));
        if let Err(e) = cleanup::remove_tree(&self.name) {
            // Do not panic while unwinding; report so that a leftover is visible.
            eprintln!("cleanup of \\{} failed: {e}", self.name);
            if !std::thread::panicking() {
                panic!("cleanup of \\{} failed: {e}", self.name);
            }
        }
    }
}

/// Test-only removal of a `\PurgeTest-*` tree through the `windows` crate directly (the module under
/// test never removes folders).
mod cleanup {
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows::Win32::System::TaskScheduler::{
        ITaskFolder, ITaskService, TASK_ENUM_HIDDEN, TaskScheduler,
    };
    use windows::Win32::System::Variant::VARIANT;
    use windows::core::{BSTR, Result};

    const NOT_FOUND: [u32; 2] = [0x8007_0002, 0x8007_0003];

    pub fn remove_tree(top: &str) -> Result<()> {
        // SAFETY: balanced below on this thread.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        let uninit = hr.is_ok();
        let r = (|| {
            // SAFETY: plain COM calls on live interfaces.
            unsafe {
                let svc: ITaskService =
                    CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
                let e = VARIANT::default();
                svc.Connect(&e, &e, &e, &e)?;
                let root = svc.GetFolder(&BSTR::from("\\"))?;
                let folder = match root.GetFolder(&BSTR::from(top)) {
                    Ok(f) => f,
                    Err(e) if NOT_FOUND.contains(&(e.code().0 as u32)) => return Ok(()),
                    Err(e) => return Err(e),
                };
                empty(&folder)?;
                drop(folder);
                root.DeleteFolder(&BSTR::from(top), 0)
            }
        })();
        if uninit {
            // SAFETY: balances the successful CoInitializeEx above; all interfaces are released.
            unsafe { CoUninitialize() };
        }
        r
    }

    /// Deletes every task and subfolder in `f`, depth first.
    unsafe fn empty(f: &ITaskFolder) -> Result<()> {
        // SAFETY: `f` is live.
        unsafe {
            let subs = f.GetFolders(0)?;
            let mut names = Vec::new();
            for i in 1..=subs.Count()? {
                let s = subs.get_Item(&VARIANT::from(i))?;
                empty(&s)?;
                names.push(s.Name()?);
            }
            drop(subs);
            for n in names {
                f.DeleteFolder(&n, 0)?;
            }
            let tasks = f.GetTasks(TASK_ENUM_HIDDEN.0)?;
            let mut names = Vec::new();
            for i in 1..=tasks.Count()? {
                names.push(tasks.get_Item(&VARIANT::from(i))?.Name()?);
            }
            drop(tasks);
            for n in names {
                f.DeleteTask(&n, 0)?;
            }
            Ok(())
        }
    }
}

#[cfg(feature = "write")]
#[test]
fn list_includes_hidden_task() {
    let dir = TestFolder::new();
    let path = dir.path(&format!("t_{}", std::process::id()));
    taskschd::register_xml(&path, &task_xml("hidden", true, false), "").unwrap();

    let all = taskschd::list_all().unwrap();
    let t = all
        .iter()
        .find(|t| t.path == path)
        .unwrap_or_else(|| panic!("{path} not listed"));
    assert!(t.hidden, "{t:?}");
    assert!(!t.unreadable, "{t:?}");
    assert!(!t.enabled, "{t:?}");
    assert_eq!(t.running, Some(false));
    // Exactly once: the walk visits each folder once.
    assert_eq!(all.iter().filter(|t| t.path == path).count(), 1);
}

#[cfg(feature = "write")]
#[test]
fn list_reports_exec_and_com_handler_actions() {
    let dir = TestFolder::new();
    let path = dir.path("Vendor\\two-actions");
    taskschd::register_xml(&path, &task_xml("two actions", false, true), "").unwrap();

    let all = taskschd::list_all().unwrap();
    let t = all
        .iter()
        .find(|t| t.path == path)
        .unwrap_or_else(|| panic!("{path} not listed"));
    assert!(!t.unreadable, "{t:?}");
    assert!(!t.hidden);
    assert_eq!(
        t.actions,
        [
            RawAction::Exec {
                path: EXEC_PATH.into(),
                arguments: Some("--never".into()),
                working_dir: Some(r"C:\PurgeTest".into()),
            },
            RawAction::ComHandler {
                clsid: COM_CLSID.into(),
                data: Some("purge-data".into()),
            },
        ]
    );
    assert_eq!(t.logon_type, Some(LogonType::InteractiveToken));
    assert_eq!(t.author.as_deref(), Some("PurgeTest"));
    assert!(
        t.user_id.is_some(),
        "Task Scheduler fills in the registering user"
    );
    // read_task reads the same thing.
    assert_eq!(taskschd::read_task(&path).unwrap().as_ref(), Some(t));
}

#[test]
fn read_xml_missing_is_none() {
    let name = random_name();
    // Missing task in an existing folder (the root), and a missing folder.
    for path in [format!("\\{name}"), format!("\\{name}\\sub\\t")] {
        assert_eq!(taskschd::read_xml(&path), Ok(None), "{path}");
        assert_eq!(taskschd::read_task(&path), Ok(None), "{path}");
    }
}

#[cfg(feature = "write")]
#[test]
fn delete_missing_is_ok() {
    let dir = TestFolder::new();
    for path in [format!("\\{}", random_name()), dir.path("sub\\t")] {
        assert_eq!(taskschd::delete(&path), Ok(()), "{path}");
        // Nothing was created on the way.
        assert_eq!(taskschd::read_xml(&path), Ok(None));
    }
    // A task deleted twice: the second delete is also Ok.
    let path = dir.path("twice");
    taskschd::register_xml(&path, &task_xml("twice", false, false), "").unwrap();
    assert!(taskschd::read_xml(&path).unwrap().is_some());
    taskschd::delete(&path).unwrap();
    assert_eq!(taskschd::read_xml(&path), Ok(None));
    assert_eq!(taskschd::delete(&path), Ok(()));
}

/// Hostile: a second registration at an existing path must neither overwrite nor touch the task.
#[cfg(feature = "write")]
#[test]
fn register_existing_is_already_exists() {
    let dir = TestFolder::new();
    let path = dir.path("existing");
    taskschd::register_xml(&path, &task_xml("original", false, true), "").unwrap();
    let before = taskschd::read_xml(&path).unwrap().unwrap();

    let other = task_xml("replacement", true, false);
    assert_eq!(
        taskschd::register_xml(&path, &other, &before.1),
        Err(WinError::AlreadyExists(path.clone()))
    );
    let after = taskschd::read_xml(&path).unwrap().unwrap();
    assert_eq!(after, before, "the existing task changed");
    assert!(after.0.contains("original"));
}

/// The spike's fidelity measure: XML and SDDL read back after delete and re-registration of the XML
/// read before. The spike's normalisation list (RESULT.json `task.normalise`) is empty, so the
/// comparison is byte for byte.
#[cfg(feature = "write")]
#[test]
fn register_then_read_xml_equal_after_spike_normalisation() {
    let dir = TestFolder::new();
    for (rel, hidden, com) in [("plain", false, false), ("Sub\\hidden-two", true, true)] {
        let path = dir.path(rel);
        taskschd::register_xml(&path, &task_xml(rel, hidden, com), "").unwrap();
        let (xml, sddl) = taskschd::read_xml(&path).unwrap().unwrap();
        let listed = taskschd::read_task(&path).unwrap().unwrap();

        taskschd::delete(&path).unwrap();
        assert_eq!(taskschd::read_xml(&path), Ok(None));

        taskschd::register_xml(&path, &xml, &sddl).unwrap();
        let (xml2, sddl2) = taskschd::read_xml(&path).unwrap().unwrap();
        assert_eq!(xml2, xml, "{rel}: XML differs after re-registration");
        assert_eq!(sddl2, sddl, "{rel}: SDDL differs after re-registration");
        assert_eq!(taskschd::read_task(&path).unwrap().unwrap(), listed);
    }
}

#[cfg(feature = "write")]
#[test]
fn register_creates_missing_parent_folder() {
    let dir = TestFolder::new();
    let path = dir.path("a\\b\\t");
    assert_eq!(taskschd::read_xml(&path), Ok(None));
    taskschd::register_xml(&path, &task_xml("nested", false, false), "").unwrap();
    let t = taskschd::read_task(&path).unwrap().unwrap();
    assert_eq!(t.path, path);
    // A sibling in the now existing folder.
    let sibling = dir.path("a\\b\\u");
    taskschd::register_xml(&sibling, &task_xml("sibling", false, false), "").unwrap();
    assert!(taskschd::read_xml(&sibling).unwrap().is_some());
}

#[test]
fn path_validation_rejects_dotdot_and_empty_segment() {
    let long = format!("\\{}", "x".repeat(taskschd::MAX_PATH_LEN));
    let bad = [
        "",
        "\\",
        "task",
        "\\\\task",
        "\\a\\\\task",
        "\\a\\",
        "\\..\\task",
        "\\a\\..\\task",
        "\\a\\..",
        "\\.\\task",
        "\\a\\.",
        "\\a/b",
        "\\a\0b",
        long.as_str(),
    ];
    for p in bad {
        let invalid = Err(WinError::InvalidPath(p.into()));
        assert_eq!(taskschd::validate_path(p), invalid, "{p:?}");
        assert_eq!(taskschd::read_xml(p).map(|_| ()), invalid, "{p:?}");
        assert_eq!(taskschd::read_task(p).map(|_| ()), invalid, "{p:?}");
        #[cfg(feature = "write")]
        {
            assert_eq!(taskschd::delete(p), invalid, "{p:?}");
            assert_eq!(
                taskschd::register_xml(p, &task_xml("x", false, false), ""),
                invalid,
                "{p:?}"
            );
        }
    }
    assert_eq!(taskschd::validate_path("\\Vendor\\Updater"), Ok(()));
}

/// The module has no call that starts, stops, ends, enables or disables a task, registers with an
/// update flag, changes a descriptor or removes a folder.
#[test]
fn no_run_stop_enable_symbols() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/taskschd.rs"))
        .expect("read src/taskschd.rs");
    for forbidden in [
        ".Run(",
        "RunEx",
        ".Stop(",
        "EndTask",
        "SetEnabled",
        "put_Enabled",
        "TASK_CREATE_OR_UPDATE",
        "TASK_UPDATE",
        "TASK_DONT_ADD_PRINCIPAL_ACE",
        "TASK_IGNORE_REGISTRATION_TRIGGERS",
        "DeleteFolder",
        "SetSecurityDescriptor",
        "RegisterTaskDefinition",
        "GetRunningTasks",
        "GetInstances",
    ] {
        assert!(
            !src.contains(forbidden),
            "src/taskschd.rs mentions {forbidden}"
        );
    }
    // The one registration uses TASK_CREATE (2) and the one delete passes flags 0.
    assert_eq!(src.matches(".RegisterTask(").count(), 1);
    assert_eq!(src.matches("TASK_CREATE.0").count(), 1);
    assert_eq!(src.matches(".DeleteTask(&name, 0)").count(), 1);
}

/// The caps of the walk on the live tree: one task more than the cap or one folder deeper is an
/// error, never a shorter list. (Exact boundaries are unit-tested in src/taskschd.rs.)
#[cfg(feature = "write")]
#[test]
fn depth_and_count_caps() {
    let dir = TestFolder::new();
    taskschd::register_xml(&dir.path("a\\b\\t"), &task_xml("deep", false, false), "").unwrap();
    let n = taskschd::list_all().unwrap().len();
    assert!(n >= 1);
    // The test folder `\PurgeTest-x\a\b` is at depth 3.
    assert!(matches!(
        taskschd::list_all_with(ListLimits {
            max_depth: 2,
            ..ListLimits::DEFAULT
        }),
        Err(WinError::TooDeep { max: 2, .. })
    ));
    assert_eq!(
        taskschd::list_all_with(ListLimits {
            max_tasks: 0,
            ..ListLimits::DEFAULT
        }),
        Err(WinError::TooManyTasks { max: 0 })
    );
}

/// The XML checks run before Task Scheduler is called.
#[cfg(feature = "write")]
#[test]
fn register_refuses_registration_trigger_and_bad_xml() {
    let dir = TestFolder::new();
    let path = dir.path("refused");
    let with_trigger = task_xml("x", false, false).replace(
        "<Principals>",
        "<Triggers><RegistrationTrigger><Enabled>false</Enabled></RegistrationTrigger></Triggers><Principals>",
    );
    for xml in [with_trigger.as_str(), "", "<Task>\0</Task>"] {
        assert!(
            matches!(
                taskschd::register_xml(&path, xml, ""),
                Err(WinError::InvalidXml(_))
            ),
            "{xml:?}"
        );
    }
    assert_eq!(taskschd::read_xml(&path), Ok(None));
}
