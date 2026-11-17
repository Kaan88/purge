//! SYS-TASK (ENGINE_PLAN.md §5.6, §5.7.2; M1b, M1B-S-TASK): scheduled tasks the app left behind.
//!
//! # Input
//!
//! The tasks of the machine as the pipeline read them once for every scanner
//! (`ctx.ext.sysobj.tasks`, one `SystemSource::tasks` call in `ScanExt::build`) and the tasks the harvest
//! recorded as the app's (`fp.sys.tasks`). The scanner reads nothing else from the registry; it asks the
//! file system whether an action's program file still exists. A task list that could not be read is
//! empty in the index and its error line is in `ctx.ext.sysobj.errors` (the scan warning); nothing is
//! offered then, recorded or not: unknown never makes a candidate.
//!
//! # Which tasks are considered
//!
//! The task's own name, its folder and its author are never a reason. A task is considered only when
//!
//! - every action is the app's: an exec action whose path resolves to one file
//!   (`purge_index::sysobj::task_programs`, the harvest's resolution) for which `ScanCtx::object_owner`
//!   answers (the file lies in an InstallRoot of the app or is one of its exe or outside-root files) and
//!   every absolute path among its arguments is a file of the app
//!   (`sys_service::arguments_are_the_apps`; R2a S5) and, when an argument may be relative, its working
//!   directory is a root of the app or inside one (`TaskPrograms::work_dirs`; R3a S6), or a COM-handler action whose CLSID is one of the app's (`fp.anchors.clsids`); or
//! - the harvest recorded a task at this path (`fp.sys.tasks`).
//!
//! A task the harvest did not record is offered only in the first case, so an action of another product,
//! a COM handler of another class, an interpreter or host (`cmd.exe`, `powershell.exe`, `rundll32.exe`,
//! ...: `Unresolved` whatever its arguments name), an action of another kind, or a definition the
//! scanning user cannot read (no actions) gives no candidate at all.
//!
//! # The guard first
//!
//! The guard's object rule (`sys.task.windows`, the baseline) is checked with the task path, with every
//! exec action's path in the form the executor's gate checks it (unquoted, canonicalised with the
//! machine layout and **no** profile, else as written, which the guard takes as under `%SystemRoot%`)
//! and with every resolved program file. A blocked task the harvest recorded is listed with the blocker
//! (Protected), so the user sees why it stays; a blocked task it did not record is not listed. One
//! consequence is stated here because the rule's name does not say it: an exec path written with a
//! per-user token (`%LOCALAPPDATA%\...`) cannot be canonicalised without a profile, the executor refuses
//! it as `sys.task.windows`, and so it is listed with that blocker, never offered.
//!
//! # Evidence and bands
//!
//! One candidate per task: `Target::Task { path }` (the path as Task Scheduler returns it),
//! `Action::DeleteKey`, `Category::Startup`, harm Low, the digest of the task read now as `object_fp`.
//! Task folders are never candidates.
//!
//! - Recorded at harvest with the same digest, every action the app's, every exec action's file proven
//!   gone now (`ScanCtx::program_gone`, R3a S1: in an InstallRoot the whole root gone on the volume the
//!   harvest recorded) and every COM-handler action's class proven unregistered (below):
//!   `OwnedSystemObject` (Tier A), which can make it Safe (D10). This covers a task whose only actions
//!   are COM handlers of the app's classes, which the harvest records since R4 B2.
//! - Recorded with the same digest but a program file present (or its state unknown), a COM handler
//!   whose class is still registered somewhere (or that cannot be shown not to be), or a program that is
//!   no longer the app's by the scan's rule (not inside an InstallRoot, not an exe): `OwnedSystemObject`
//!   lowered to Tier B with the reason: Likely.
//! - Recorded with the same digest and an action that does not resolve to one file (interpreter, host,
//!   unexpandable reference, other action kind): the soft blocker `ProgramUnresolved`: Likely.
//! - Recorded, but the definition cannot be read now: `ProgramUnresolved` and the evidence at Tier B
//!   (nothing shows that the task is the one recorded).
//! - Recorded with another digest: the hard blocker `ObjectChangedSinceHarvest` (something re-registered
//!   or edited the task during or after the uninstall).
//! - Not recorded, every action the app's: `OwnedSystemObject` is requested without the harvest record,
//!   which the builder turns into `PointsIntoInstallRoot` (Value scope, it never supports an object):
//!   Likely at most.
//! - A task that runs with a stored password cannot be registered again without it (spike: `0x8007052E`):
//!   `Reversibility::Partial` and the soft blocker `ReversibilityPartial`, never preselected.
//! - A program file that lies in, or is referenced by, another installed app (`ctx.other_apps`) adds that
//!   app's blocker.
//!
//! A recorded task that is gone now gives nothing: there is nothing left to remove.
//!
//! # A COM handler's class (R4 B2)
//!
//! A class is gone when its `CLSID\{x}` key is absent (`NotFound`, nothing else) in both registry views
//! of the machine's Classes and of the Classes of every user whose hive is loaded, the fingerprint's user
//! and the user of a per-user registration included; each such user's `HKU\<SID>_Classes` must itself be
//! there (a hive that is not loaded proves nothing). A key that is present, even with its server
//! missing, keeps the task Likely: COM-CLASS judges the key. The read is made only for a task that is
//! otherwise Safe: at most two opens per view per COM-handler action, and one list of the loaded hives.

use std::collections::HashSet;

use purge_guard::deny::DenyList;
use purge_guard::prefix;
use purge_index::sysobj::{Env, ProgramRef, task_programs};
use purge_model::object::{TaskAction, TaskIdentity};
use purge_model::{Action, Blocker, Candidate, Category, Harm, ObjectWhy, Reversibility, Target};
use purge_source::sysobj::TaskInfo;
use purge_source::types::ExistsState;

use crate::com_class::is_braced_guid;
use crate::framework::{AppIdentityView, CandidateBuilder, RootSpec, ScanCtx, Scanner};
use crate::sys_service::arguments_are_the_apps;

/// The scanner's catalog id.
pub const ID: &str = "SYS-TASK";

/// The machine's Classes, where a COM handler's class is looked up (with each loaded user's).
const MACHINE_CLASSES: &str = r"HKLM\SOFTWARE\Classes";

/// Task Scheduler's registry cache: where the rig captures what the task list says.
const TASK_CACHE: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache";

/// The prefix of the index's error line for a task list it could not read (`purge_index::sysobj`).
const LIST_UNREADABLE: &str = "sysobj: tasks:";

/// The scanner reads the task list of `SystemSource::tasks` through `ScanExt`; the rig captures it
/// together with Task Scheduler's registry cache.
const ROOTS: &[RootSpec] = &[RootSpec::reg(TASK_CACHE, None)];

/// Why an owned task is not proven to be the recorded one with its programs gone.
const WHY_UNREADABLE: &str = "the task's definition cannot be read now";
const WHY_CHANGED: &str = "the task differs from the one recorded at harvest";
const WHY_FOREIGN: &str =
    "an action no longer runs a file of the app (not in an InstallRoot, not one of its exes)";
const WHY_PRESENT: &str = "an action's program file still exists or its state is unknown";
const WHY_COM: &str =
    "a COM-handler action's class is still registered, or cannot be shown not to be";

/// The SYS-TASK scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SysTask;

impl Scanner for SysTask {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
        let tasks = &ctx.ext.sysobj.tasks;
        let recorded_tasks = &ctx.fp.sys.tasks;
        // The list itself could not be read: the index's error is a scan warning; what it hides of the
        // app is said here.
        if ctx
            .ext
            .sysobj
            .errors
            .iter()
            .any(|e| e.starts_with(LIST_UNREADABLE))
            && !recorded_tasks.is_empty()
        {
            ctx.ext.warn(
                ID,
                format!(
                    "the task list could not be read; the {} task(s) recorded at harvest are not \
                     offered",
                    recorded_tasks.len()
                ),
            );
        }
        if tasks.is_empty() {
            return Vec::new();
        }
        // A task whose definition cannot be read is attributed only through the harvest's record; the
        // others are left out, which is said once.
        let unread = tasks
            .iter()
            .filter(|t| {
                t.identity.actions.is_empty()
                    && !recorded_tasks
                        .iter()
                        .any(|r| prefix::eq_ci(&r.identity.path, &t.identity.path))
            })
            .count();
        if unread > 0 {
            ctx.ext.warn(
                ID,
                format!(
                    "{unread} task(s) whose definition could not be read are not attributed to any app"
                ),
            );
        }
        let env = Env::new(ctx.env.iter());
        let deny = DenyList::compile(ctx.guard);
        let mut seen: HashSet<String> = HashSet::new();
        let mut out = Vec::new();
        for task in tasks {
            // One candidate per task path, the first the list returns.
            if !is_task_path(&task.identity.path) || !seen.insert(prefix::fold(&task.identity.path))
            {
                continue;
            }
            if let Some(candidate) = judge(ctx, &deny, &env, task) {
                out.push(candidate);
            }
        }
        out
    }
}

/// Whether `path` names a task (`\Folder\Name`), not the root or a folder (`\Folder\`).
fn is_task_path(path: &str) -> bool {
    path.starts_with('\\')
        && !path.ends_with(['\\', '/'])
        && path
            .split(['\\', '/'])
            .skip(1)
            .all(|s| !s.trim().is_empty())
}

/// What one action of a task is, for the app.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Act {
    /// An exec action running a file of the app.
    Own { file: String, why: ObjectWhy },
    /// A COM-handler action of one of the app's classes (`clsid` as the action names it, trimmed).
    OwnCom { clsid: String },
    /// An exec action running a file that is not the app's (`file`), or a COM handler of another class
    /// (`file` is `None`).
    Foreign { file: Option<String> },
    /// An action that cannot be told to run one file: an interpreter or host, a path that does not
    /// resolve, an action of another kind.
    Unresolved,
}

impl Act {
    fn is_own(&self) -> bool {
        matches!(self, Act::Own { .. } | Act::OwnCom { .. })
    }

    fn file(&self) -> Option<&str> {
        match self {
            Act::Own { file, .. } | Act::Foreign { file: Some(file) } => Some(file),
            _ => None,
        }
    }
}

/// Classifies every action of `identity` (C-SYSOBJ `task_programs`; COM handlers through the app's
/// CLSID anchors).
fn classify(ctx: &ScanCtx<'_>, env: &Env, identity: &TaskIdentity) -> Vec<Act> {
    let programs = task_programs(identity, env);
    identity
        .actions
        .iter()
        .zip(programs.actions)
        .zip(programs.arg_paths)
        .zip(programs.work_dirs)
        .map(|(((action, program), args), dir)| match action {
            TaskAction::ComHandler { clsid, .. } => {
                let clsid = clsid.trim();
                let own = !clsid.is_empty()
                    && ctx
                        .fp
                        .anchors
                        .clsids
                        .iter()
                        .any(|c| prefix::eq_ci(c.trim(), clsid));
                if own {
                    Act::OwnCom {
                        clsid: clsid.to_owned(),
                    }
                } else {
                    Act::Foreign { file: None }
                }
            }
            TaskAction::Exec { .. } => match &program {
                ProgramRef::File(file) => match ctx
                    .object_owner(&program)
                    .filter(|_| arguments_are_the_apps(ctx, &args))
                    .filter(|_| dir.as_ref().is_none_or(|d| work_dir_is_the_apps(ctx, d)))
                {
                    Some(why) => Act::Own {
                        file: file.clone(),
                        why,
                    },
                    None => Act::Foreign {
                        file: Some(file.clone()),
                    },
                },
                ProgramRef::Unresolved { .. } | ProgramRef::None => Act::Unresolved,
            },
            TaskAction::Other { .. } => Act::Unresolved,
        })
        .collect()
}

/// The candidate for one task, or `None` when the task is not offered. See the module documentation.
fn judge(ctx: &ScanCtx<'_>, deny: &DenyList, env: &Env, task: &TaskInfo) -> Option<Candidate> {
    let identity = &task.identity;
    let recorded = ctx
        .fp
        .sys
        .tasks
        .iter()
        .find(|t| prefix::eq_ci(&t.identity.path, &identity.path));
    let readable = !identity.actions.is_empty();
    let acts = classify(ctx, env, identity);
    let all_own = readable && acts.iter().all(Act::is_own);
    if recorded.is_none() && !all_own {
        return None;
    }
    let target = Target::Task {
        path: identity.path.clone(),
    };
    let now = identity.fp();
    // The guard's object rules as the framework judges them (R3a M5: one place). `task` is the index's
    // first task of this path, which the framework looks up too.
    let guard = ctx.object_guard(deny, &target, Some(&now)).ok().flatten();
    if guard.is_some() && recorded.is_none() {
        return None;
    }

    let mut b = ctx.candidate(ID, target, Action::DeleteKey, Category::Startup);
    b = b.object_fp(now);
    b.harm(Harm::Low);
    match recorded {
        None => {
            // Every action is the app's (above); the harvest did not record the task.
            b = b.owned_system_object(unrecorded_why(&acts), false);
        }
        Some(rec) => {
            b = b.owned_system_object(rec.why, true);
            if !readable {
                b.cap_at_tier_b(WHY_UNREADABLE)
                    .blocker(Blocker::ProgramUnresolved);
            } else if rec.identity.fp() != identity.fp() {
                b.cap_at_tier_b(WHY_CHANGED)
                    .blocker(Blocker::ObjectChangedSinceHarvest);
            } else if acts.contains(&Act::Unresolved) {
                b.blocker(Blocker::ProgramUnresolved);
            } else if !all_own {
                b.cap_at_tier_b(WHY_FOREIGN);
            } else if !programs_gone(ctx, &acts) {
                b.cap_at_tier_b(WHY_PRESENT);
            } else if !classes_gone(ctx, &acts) {
                b.cap_at_tier_b(WHY_COM);
            }
        }
    }
    if let Some(blocker) = guard {
        b.blocker(blocker);
    }
    other_app_blockers(ctx, &mut b, &acts);
    if task.stored_password {
        b.reversibility(Reversibility::Partial)
            .blocker(Blocker::ReversibilityPartial);
    }
    Some(b.build())
}

/// The `why` of a task the harvest did not record, all of whose actions are the app's: the program is
/// one of the app's exes when any exec action's file is (the harvest's rule); the app's class when
/// there is no exec action; otherwise in a root.
fn unrecorded_why(acts: &[Act]) -> ObjectWhy {
    if !acts.iter().any(|a| matches!(a, Act::Own { .. })) {
        ObjectWhy::AppComClass
    } else if acts.iter().any(|a| {
        matches!(
            a,
            Act::Own {
                why: ObjectWhy::ProgramIsAppExe,
                ..
            }
        )
    }) {
        ObjectWhy::ProgramIsAppExe
    } else {
        ObjectWhy::ProgramInRoot
    }
}

/// Whether every exec action's file is proven gone ([`ScanCtx::program_gone`], R3a S1: the dangling
/// rule's proof, not a bare "absent"). Called only for tasks whose every action is the app's; a
/// COM-handler action is judged by [`classes_gone`], and a task needs at least one action.
fn programs_gone(ctx: &ScanCtx<'_>, acts: &[Act]) -> bool {
    let mut any = false;
    for act in acts {
        match act {
            Act::Own { file, .. } => {
                if !ctx.program_gone(file) {
                    return false;
                }
                any = true;
            }
            Act::OwnCom { .. } => any = true,
            Act::Foreign { .. } | Act::Unresolved => return false,
        }
    }
    any
}

/// Whether the class of every COM-handler action is proven unregistered (R4 B2; module documentation
/// "A COM handler's class"). `true` for a task without COM-handler actions, without a read.
fn classes_gone(ctx: &ScanCtx<'_>, acts: &[Act]) -> bool {
    let clsids: Vec<&str> = acts
        .iter()
        .filter_map(|a| match a {
            Act::OwnCom { clsid } => Some(clsid.as_str()),
            _ => None,
        })
        .collect();
    if clsids.is_empty() {
        return true;
    }
    if !clsids.iter().all(|c| is_braced_guid(c)) {
        return false;
    }
    let Ok(loaded) = ctx.reg.loaded_user_sids() else {
        return false;
    };
    let mut users: Vec<String> = Vec::new();
    for sid in [
        Some(ctx.fp.user_sid.as_str()),
        ctx.fp.app.program_id.hive_sid(),
    ]
    .into_iter()
    .flatten()
    .chain(loaded.iter().map(String::as_str))
    {
        let sid = sid.trim();
        let is_user = (sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-"))
            && !prefix::fold(sid).ends_with("_classes")
            && !sid.contains(prefix::SEP);
        if is_user && !users.iter().any(|u| prefix::eq_ci(u, sid)) {
            users.push(sid.to_owned());
        }
    }
    let mut roots: Vec<String> = vec![MACHINE_CLASSES.to_owned()];
    for sid in &users {
        let root = format!(r"HKU\{sid}_Classes");
        if ctx.reg.key_exists(&root) != ExistsState::Present {
            return false;
        }
        roots.push(root);
    }
    clsids.iter().all(|clsid| {
        roots.iter().all(|root| {
            [
                format!(r"{root}\CLSID\{clsid}"),
                format!(r"{root}\WOW6432Node\CLSID\{clsid}"),
            ]
            .iter()
            .all(|key| ctx.reg.key_exists(key) == ExistsState::Absent)
        })
    })
}

/// Whether a task action's working directory (`TaskPrograms::work_dirs`, set when an argument may be
/// relative to it) is the app's: a root of the app or inside one (R3a S6).
fn work_dir_is_the_apps(ctx: &ScanCtx<'_>, dir: &ProgramRef) -> bool {
    match dir {
        ProgramRef::File(dir) => ctx.fp.roots.iter().any(|r| {
            !prefix::steps_back(dir)
                && (prefix::is_same(dir, &r.path) || prefix::is_inside(dir, &r.path))
        }),
        ProgramRef::Unresolved { .. } | ProgramRef::None => false,
    }
}

/// The blockers of another installed app whose root holds, or whose records name, a program file of
/// the task.
fn other_app_blockers(ctx: &ScanCtx<'_>, b: &mut CandidateBuilder<'_>, acts: &[Act]) {
    for file in acts.iter().filter_map(Act::file) {
        for blocker in ctx.other_apps.path_blockers(file) {
            if matches!(
                blocker,
                Blocker::InsideOtherApp { .. } | Blocker::ReferencedByOtherApp { .. }
            ) {
                b.blocker(blocker);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_paths_and_folders() {
        for (path, want) in [
            (r"\Vendor\Update", true),
            (r"\Update", true),
            (r"\", false),
            (r"\Vendor\", false),
            (r"Vendor\Update", false),
            (r"\Vendor\\Update", false),
            ("", false),
        ] {
            assert_eq!(is_task_path(path), want, "{path:?}");
        }
    }
}
