//! Deny rules for system objects: services, tasks, firewall rules (M1b, C-GUARD).
//!
//! A typed object is not a location, so the path and key rules of the deny-list never see it. It is
//! judged here from facts the caller reads (at scan time, and again by the executor gate at validate and
//! act time): [`check_object`] is pure and does no I/O. Every rule is absolute: no exemption lifts it.
//!
//! The rules, in the order in which the first that applies is reported:
//!
//! | rule | kind | applies when |
//! |---|---|---|
//! | `sys.driver` | service | the type has a driver bit (`0x1`, `0x2`, `0x4`, `0x8`), or the type is unknown |
//! | `sys.service.peruser` | service | a per-user template or instance (flag, or type bit `0x40`/`0x80`) |
//! | `sys.service.marked` | service | `DeleteFlag` is already set |
//! | `WindowsBaseline` | any | the object is in the Windows baseline |
//! | `sys.service.windows` | service | the program is under `%SystemRoot%`, at any depth (for a service hosted by svchost the callers pass its `ImagePath` command, the host, never its `ServiceDll`: every such service is Windows') |
//! | `sys.task.windows` | task | the task is under `\Microsoft\Windows\`, `\Microsoft\Office\` or `\Microsoft\EdgeUpdate*`, or its program is under `%SystemRoot%` |
//! | `fw.package-bound` | firewall rule | bound to an AppX package or AppContainer |
//! | `fw.resource-name` | firewall rule | its name is a resource reference (`@...`) |
//!
//! `%SystemRoot%` is recognised lexically: a leading `%SystemRoot%` or `%windir%` token, the NT form
//! `\SystemRoot\`, a path relative to the Windows directory (as a driver's `ImagePath` may be), a path
//! rooted on the current drive with `\Windows\` as its first segment, and `<drive>:\Windows\...`.
//! [`DenyList::check_object`](super::DenyList::check_object) also matches the Windows directory of its
//! `GuardEnv`, wherever it is; callers that hold a deny-list use that form.

use purge_model::{Blocker, ObjectKind};

use super::ids;
use super::pattern::{glob_match, split_fold};
use crate::prefix::fold;

/// The facts [`check_object`] judges an object by. The caller reads them fresh for each check.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ObjectGuardFacts<'a> {
    /// The service name, the task path (`\Folder\Name`, as Task Scheduler returns it) or the firewall
    /// rule's id.
    pub name_or_path_or_id: &'a str,
    /// The object's program resolved to one file (C-SYSOBJ `ProgramRef::File`), when it has one; for a
    /// service hosted by svchost, its `ImagePath` command (C-SYSOBJ `ServiceFacts::guard_program`). `None`
    /// when unresolved or absent: then no program rule applies here (the scanners treat an unresolved
    /// program as `ProgramUnresolved`).
    pub program: Option<&'a str>,
    /// A service's `Type`. `None` for a service means the type could not be read, which blocks it as
    /// `sys.driver` (fail closed). Ignored for tasks and firewall rules.
    pub service_type: Option<u32>,
    /// A service's `DeleteFlag` is set.
    pub delete_flag: bool,
    /// A per-user service template or instance (C-SYSOBJ `per_user_template`).
    pub per_user_template: bool,
    /// A firewall rule bound to an AppX package or AppContainer (C-SYSOBJ `package_bound`).
    pub package_bound: bool,
    /// A firewall rule whose `Name` or `EmbedCtxt` starts with `@` (C-SYSOBJ `resource_name`).
    pub resource_name: bool,
    /// The object is in the Windows baseline of this build.
    pub in_baseline: bool,
}

/// The service type bits of a driver: kernel driver, file system driver, adapter, recognizer driver.
const DRIVER_BITS: u32 = 0x1 | 0x2 | 0x4 | 0x8;
/// `SERVICE_USER_SERVICE` and `SERVICE_USERSERVICE_INSTANCE`.
const PER_USER_BITS: u32 = 0x40 | 0x80;

/// Task folders that hold Windows' (and Office's, and Edge's updater's) own tasks: the first two
/// segments of the task path, folded; the second may be a glob.
const WINDOWS_TASK_FOLDERS: [&str; 3] = ["windows", "office", "edgeupdate*"];

/// The blocker for a typed object, or `None` when no object rule applies. See the module documentation
/// for the rules and their order. Pure.
pub fn check_object(kind: ObjectKind, facts: &ObjectGuardFacts<'_>) -> Option<Blocker> {
    check_object_in(kind, facts, None)
}

/// [`check_object`], with the folded segments of the Windows directory when the caller knows it.
pub(super) fn check_object_in(
    kind: ObjectKind,
    facts: &ObjectGuardFacts<'_>,
    windir: Option<&[String]>,
) -> Option<Blocker> {
    let deny = |rule: &str| {
        Some(Blocker::DenyListed {
            rule: rule.to_owned(),
        })
    };
    if kind == ObjectKind::Service {
        let ty = facts.service_type;
        if ty.is_none_or(|t| t & DRIVER_BITS != 0) {
            return deny(ids::SYS_DRIVER);
        }
        if facts.per_user_template || ty.is_some_and(|t| t & PER_USER_BITS != 0) {
            return deny(ids::SYS_SERVICE_PERUSER);
        }
        if facts.delete_flag {
            return deny(ids::SYS_SERVICE_MARKED);
        }
    }
    if facts.in_baseline {
        return Some(Blocker::WindowsBaseline);
    }
    let windows_program = facts
        .program
        .is_some_and(|program| under_system_root(program, windir));
    match kind {
        ObjectKind::Service if windows_program => deny(ids::SYS_SERVICE_WINDOWS),
        ObjectKind::Task if windows_program || windows_task_path(facts.name_or_path_or_id) => {
            deny(ids::SYS_TASK_WINDOWS)
        }
        ObjectKind::FirewallRule if facts.package_bound => deny(ids::FW_PACKAGE_BOUND),
        ObjectKind::FirewallRule if facts.resource_name => deny(ids::FW_RESOURCE_NAME),
        _ => None,
    }
}

/// Whether a task path lies in one of [`WINDOWS_TASK_FOLDERS`] under `\Microsoft`, at any depth below it.
/// Separators may be either slash; case does not matter.
fn windows_task_path(path: &str) -> bool {
    let segs: Vec<String> = path
        .split(['\\', '/'])
        .filter(|s| !s.is_empty())
        .map(fold)
        .collect();
    segs.len() >= 2
        && segs[0] == "microsoft"
        && WINDOWS_TASK_FOLDERS
            .iter()
            .any(|folder| glob_match(folder, &segs[1]))
}

/// Whether a program path lies under `%SystemRoot%`, at any depth. See the module documentation for the
/// forms recognised. A program that is not a drive path, a rooted path or a token form (a relative path,
/// an empty string) counts as under it: a service's relative `ImagePath` is relative to the Windows
/// directory, and anything else is not a resolved file.
fn under_system_root(program: &str, windir: Option<&[String]>) -> bool {
    let mut p = program.trim().trim_matches('"');
    for prefix in [r"\\?\", r"\??\"] {
        if let Some(rest) = p.strip_prefix(prefix) {
            p = rest;
        }
    }
    let segs = split_fold(&p.replace('/', "\\"));
    let Some(first) = segs.first() else {
        return true;
    };
    if matches!(first.as_str(), "%systemroot%" | "%windir%") {
        return true;
    }
    if p.starts_with(r"\\") || p.starts_with("//") {
        // A UNC path: never the local Windows directory.
        return false;
    }
    let drive = first.len() == 2 && first.ends_with(':');
    if drive {
        let default_layout = segs.get(1).is_some_and(|s| s == "windows");
        let actual =
            windir.is_some_and(|w| w.len() >= 2 && segs.len() > w.len() && segs.starts_with(w));
        return default_layout || actual;
    }
    if p.starts_with(['\\', '/']) {
        // Rooted on the current drive: `\SystemRoot\...` (NT) or `\Windows\...`.
        let rest_windir = windir.is_some_and(|w| {
            w.len() >= 2 && segs.len() >= w.len() && segs[..w.len() - 1] == w[1..]
        });
        return matches!(first.as_str(), "systemroot" | "windows") || rest_windir;
    }
    // Relative: resolved against the Windows directory.
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_root_forms() {
        let windir = split_fold(r"D:\WinNT");
        for (program, want) in [
            (r"C:\Windows\System32\svchost.exe", true),
            (r"c:\windows\system32\drivers\x.sys", true),
            (r"%SystemRoot%\System32\x.exe", true),
            (r"%windir%\x.exe", true),
            (r"\SystemRoot\System32\drivers\x.sys", true),
            (r"System32\drivers\x.sys", true),
            (r"\??\C:\Windows\x.sys", true),
            (r"\\?\C:\Windows\x.exe", true),
            (r#""C:\Windows\x.exe""#, true),
            (r"D:\WinNT\System32\x.exe", true),
            (r"\WinNT\System32\x.exe", true),
            ("", true),
            (r"C:\Program Files\App\app.exe", false),
            (r"C:\WindowsApps\x.exe", false),
            (r"C:\App\Windows\x.exe", false),
            (r"\\server\share\Windows\x.exe", false),
            (r"D:\WinNTX\x.exe", false),
        ] {
            assert_eq!(under_system_root(program, Some(&windir)), want, "{program}");
        }
        // Without the GuardEnv, a Windows directory elsewhere is not seen.
        assert!(!under_system_root(r"D:\WinNT\System32\x.exe", None));
    }

    #[test]
    fn task_folders() {
        for (path, want) in [
            (r"\Microsoft\Windows\Defrag\ScheduledDefrag", true),
            (r"\microsoft\windows\x", true),
            (r"\Microsoft\Office\OfficeTelemetryAgentLogOn", true),
            (r"\Microsoft\EdgeUpdate\Task", true),
            (r"\Microsoft\EdgeUpdateTaskMachineCore", true),
            (r"/Microsoft/Windows/x", true),
            (r"\Microsoft\VisualStudio\Updates\x", false),
            (r"\MicrosoftEdgeUpdateTaskMachineCore", false),
            (r"\Vendor\Microsoft\Windows\x", false),
            (r"\Microsoft", false),
            (r"\App Updater", false),
        ] {
            assert_eq!(windows_task_path(path), want, "{path}");
        }
    }
}
