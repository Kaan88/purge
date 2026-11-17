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
//!   answers (the file lies in an InstallRoot of the app or is one of its exe or outside-root files), or a
//!   COM-handler action whose CLSID is one of the app's (`fp.anchors.clsids`); or
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
//!   absent now and no COM-handler action: `OwnedSystemObject` (Tier A), which can make it Safe (D10).
//!   A COM handler's class could be shown dangling only by reading its `CLSID` keys, which this scanner's
//!   budget (no key opens) does not allow; such a task is at most Likely.
//! - Recorded with the same digest but a program file present (or its state unknown), a COM-handler
//!   action, or a program that is no longer the app's by the scan's rule (not inside an InstallRoot, not
//!   an exe): `OwnedSystemObject` lowered to Tier B with the reason: Likely.
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

use std::collections::HashSet;

use purge_guard::canon::canon_path;
use purge_guard::deny::{DenyList, ObjectGuardFacts};
use purge_guard::prefix;
use purge_index::sysobj::{Env, ProgramRef, task_programs};
use purge_model::object::{TaskAction, TaskIdentity};
use purge_model::{
    Action, Blocker, Candidate, Category, Harm, ObjectKind, ObjectWhy, Reversibility, Target,
};
use purge_source::sysobj::TaskInfo;

use crate::framework::{AppIdentityView, CandidateBuilder, RootSpec, ScanCtx, Scanner};

/// The scanner's catalog id.
pub const ID: &str = "SYS-TASK";

/// Task Scheduler's registry cache: where the rig captures what the task list says.
const TASK_CACHE: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache";

/// The tasks' tree in the registry, where the baseline records which tasks Windows has (the key the
/// harvest's baseline check uses: this prefix followed by the task path).
const TASK_TREE: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";

/// The scanner reads the task list of `SystemSource::tasks` through `ScanExt`; the rig captures it
/// together with Task Scheduler's registry cache.
const ROOTS: &[RootSpec] = &[RootSpec::reg(TASK_CACHE, None)];

/// Why an owned task is not proven to be the recorded one with its programs gone.
const WHY_UNREADABLE: &str = "the task's definition cannot be read now";
const WHY_CHANGED: &str = "the task differs from the one recorded at harvest";
const WHY_FOREIGN: &str =
    "an action no longer runs a file of the app (not in an InstallRoot, not one of its exes)";
const WHY_PRESENT: &str = "an action's program file still exists or its state is unknown";
const WHY_COM: &str = "a COM-handler action's class cannot be shown gone";

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
        if tasks.is_empty() {
            return Vec::new();
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
    /// A COM-handler action of one of the app's classes.
    OwnCom,
    /// An exec action running a file that is not the app's (`file`), or a COM handler of another class
    /// (`file` is `None`).
    Foreign { file: Option<String> },
    /// An action that cannot be told to run one file: an interpreter or host, a path that does not
    /// resolve, an action of another kind.
    Unresolved,
}

impl Act {
    fn is_own(&self) -> bool {
        matches!(self, Act::Own { .. } | Act::OwnCom)
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
        .map(|(action, program)| match action {
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
                    Act::OwnCom
                } else {
                    Act::Foreign { file: None }
                }
            }
            TaskAction::Exec { .. } => match &program {
                ProgramRef::File(file) => match ctx.object_owner(&program) {
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
    let guard = guard_blocker(ctx, deny, identity, &acts);
    if guard.is_some() && recorded.is_none() {
        return None;
    }

    let mut b = ctx.candidate(
        ID,
        Target::Task {
            path: identity.path.clone(),
        },
        Action::DeleteKey,
        Category::Startup,
    );
    b = b.object_fp(identity.fp());
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
            } else if acts.contains(&Act::OwnCom) {
                b.cap_at_tier_b(WHY_COM);
            } else if !programs_gone(ctx, &acts) {
                b.cap_at_tier_b(WHY_PRESENT);
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
/// one of the app's exes when any exec action's file is (the harvest's rule); otherwise in a root.
fn unrecorded_why(acts: &[Act]) -> ObjectWhy {
    if acts.iter().any(|a| {
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

/// Whether every exec action's file is proven absent (not "unknown"). Called only for tasks with at
/// least one exec action of the app and no other kind.
fn programs_gone(ctx: &ScanCtx<'_>, acts: &[Act]) -> bool {
    let mut any = false;
    for act in acts {
        match act {
            Act::Own { file, .. } => {
                if !ctx.fs.exists(file).is_absent() {
                    return false;
                }
                any = true;
            }
            _ => return false,
        }
    }
    any
}

/// `path` without one pair of surrounding double quotes and outer blanks (the executor's form).
fn unquote(path: &str) -> &str {
    let t = path.trim();
    t.strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(t)
        .trim()
}

/// The guard's object rule for the task (see the module documentation): the path (with the baseline),
/// then every exec action's path as the executor's gate checks it, then every resolved program file.
fn guard_blocker(
    ctx: &ScanCtx<'_>,
    deny: &DenyList,
    identity: &TaskIdentity,
    acts: &[Act],
) -> Option<Blocker> {
    let in_baseline = ctx
        .baseline
        .is_some_and(|b| b.has_key(&format!("{TASK_TREE}{}", identity.path)));
    let base = ObjectGuardFacts {
        name_or_path_or_id: &identity.path,
        in_baseline,
        ..ObjectGuardFacts::default()
    };
    if let Some(blocker) = deny.check_object(ObjectKind::Task, &base) {
        return Some(blocker);
    }
    let check = |program: &str| {
        deny.check_object(
            ObjectKind::Task,
            &ObjectGuardFacts {
                program: Some(program),
                ..base
            },
        )
    };
    for action in &identity.actions {
        if let TaskAction::Exec { path, .. } = action {
            let plain = unquote(path);
            let as_gate = canon_path(plain, ctx.guard, None)
                .map(|c| c.path)
                .unwrap_or_else(|_| plain.to_owned());
            if let Some(blocker) = check(&as_gate) {
                return Some(blocker);
            }
        }
    }
    acts.iter().filter_map(Act::file).find_map(check)
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

    #[test]
    fn unquote_is_the_executors() {
        assert_eq!(unquote(r#" "C:\A b\x.exe" "#), r"C:\A b\x.exe");
        assert_eq!(unquote(r#""C:\x.exe"#), r#""C:\x.exe"#);
        assert_eq!(unquote(r"C:\x.exe"), r"C:\x.exe");
    }
}
