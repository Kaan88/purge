//! Harvest of the system objects an app registered: services, scheduled tasks, firewall rules (M1b,
//! contract C-FP `sys`, ENGINE_PLAN.md §5.6).
//!
//! The objects come from the [`SysObjectIndex`] built once per harvest; nothing is read here. An object
//! is recorded as the app's only when its program, resolved to one file
//! ([`purge_index::sysobj::ProgramRef::File`]), is the app's at harvest time:
//!
//! - [`ObjectWhy::MsiServiceRow`]: a service whose name is a `ServiceInstall` row of the app's own MSI
//!   **and** whose program lies inside an InstallRoot of the fingerprint;
//! - [`ObjectWhy::ProgramInRoot`]: the program lies inside an InstallRoot of the fingerprint. An
//!   inferred root (`DisplayIcon`, the uninstaller's folder) or a referenced data folder is a guess or
//!   the app's data, never where its programs are known to be (R2a S4), as on the scan side
//!   (`ScanCtx::object_owner`);
//! - [`ObjectWhy::ProgramIsAppExe`]: the program is one of the app's exes or one of the files its
//!   installer declares outside the roots.
//!
//! A name is never a reason: a service, task or rule named like the app but running something else is
//! not recorded. Neither is an object whose command line names, as an argument, an absolute path that is
//! not inside a root of the fingerprint (any kind) and not one of the app's files, or one that cannot be
//! told to be one local file (`purge_index::sysobj::argument_paths`):
//! `"C:\App\launcher.exe" C:\Other\svc.dll` runs another product's code (R2a S5).
//!
//! A task is recorded only when **every** exec action runs a file of the app, no action is of an
//! unknown kind, and every COM-handler action names one of the app's own CLSIDs. A program that is
//! an interpreter or host (`cmd.exe`, `rundll32.exe`, ...) is unresolved and never the app's. An object
//! [`DenyList::check_object`] blocks (drivers, per-user services, objects marked for delete, Windows'
//! own, AppX-bound or resource-named rules) is not recorded.
//!
//! Every recorded object stores its identity as read; the scanner compares its digest after the
//! uninstall. At most [`MAX_OBJECTS`] objects are recorded; beyond that the lists are cut with a warning.

use purge_guard::deny::{DenyList, ObjectGuardFacts};
use purge_guard::prefix;
use purge_index::baseline::Baseline;
use purge_index::sysobj::{
    Env, FIREWALL_RULES_KEY, ProgramRef, SERVICES_KEY, SysObjectIndex, task_programs,
};
use purge_model::object::TaskAction;
use purge_model::{
    AppFileOutsideRoot, ExeFile, ObjectKind, ObjectWhy, Root, RootKind, SysFirewallRule,
    SysObjects, SysService, SysTask,
};

/// Most system objects recorded per fingerprint.
pub const MAX_OBJECTS: usize = 500;

/// The scheduled tasks' tree in the registry, where the baseline records which tasks Windows has.
const TASK_TREE: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";

/// What [`record`] judges the objects against.
#[derive(Clone, Copy)]
pub struct SysInput<'a> {
    /// The system objects of the machine.
    pub index: &'a SysObjectIndex,
    /// The fingerprint's roots.
    pub roots: &'a [Root],
    /// The fingerprint's exe set.
    pub exes: &'a [ExeFile],
    /// The files the app's installer declares outside the roots.
    pub outside: &'a [AppFileOutsideRoot],
    /// Service names of the `ServiceInstall` rows of the app's own MSI products.
    pub msi_services: &'a [String],
    /// The app's CLSIDs (COM-handler task actions).
    pub clsids: &'a [String],
    /// The deny-list (object rules).
    pub deny: &'a DenyList,
    /// The baseline of this Windows, when there is one.
    pub baseline: Option<&'a Baseline>,
    /// The machine environment, for task action paths.
    pub env: &'a Env,
}

/// What [`record`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SysHarvest {
    /// The recorded objects, each list sorted.
    pub objects: SysObjects,
    /// Lines for the fingerprint's warnings.
    pub warnings: Vec<String>,
}

/// How a file is the app's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owned {
    InRoot,
    AppFile,
}

fn is_app_file(file: &str, inp: &SysInput<'_>) -> bool {
    inp.exes.iter().any(|e| prefix::is_same(&e.path, file))
        || inp.outside.iter().any(|o| prefix::is_same(&o.path, file))
}

/// How the program `file` is the app's: inside an InstallRoot, or one of its files. Every absolute
/// argument (`args`) must be a file inside a root of the app (any kind) or one of its files; an
/// argument that does not resolve to one file, or that lies elsewhere, makes nothing the app's.
fn owned(file: &str, args: &[ProgramRef], inp: &SysInput<'_>) -> Option<Owned> {
    let args_own = args.iter().all(|arg| match arg {
        ProgramRef::File(path) => {
            inp.roots.iter().any(|r| prefix::is_inside(path, &r.path)) || is_app_file(path, inp)
        }
        ProgramRef::Unresolved { .. } | ProgramRef::None => false,
    });
    if !args_own {
        return None;
    }
    let in_install_root = inp
        .roots
        .iter()
        .filter(|r| r.kind == RootKind::InstallRoot)
        .any(|r| prefix::is_inside(file, &r.path));
    if in_install_root {
        return Some(Owned::InRoot);
    }
    is_app_file(file, inp).then_some(Owned::AppFile)
}

fn why_of(owned: Owned) -> ObjectWhy {
    match owned {
        Owned::InRoot => ObjectWhy::ProgramInRoot,
        Owned::AppFile => ObjectWhy::ProgramIsAppExe,
    }
}

/// Records the services, tasks and firewall rules of the app. See the module documentation.
pub fn record(inp: &SysInput<'_>) -> SysHarvest {
    let mut out = SysHarvest::default();
    let objects = &mut out.objects;

    for service in &inp.index.services {
        let ProgramRef::File(program) = &service.program else {
            continue;
        };
        let Some(how) = owned(program, &service.arg_paths, inp) else {
            continue;
        };
        let name = service.identity.name.as_str();
        let facts = ObjectGuardFacts {
            name_or_path_or_id: name,
            program: Some(program),
            service_type: Some(service.identity.service_type),
            delete_flag: service.delete_flag,
            per_user_template: service.per_user_template,
            package_bound: false,
            resource_name: false,
            in_baseline: inp
                .baseline
                .is_some_and(|b| b.has_key(&format!("{SERVICES_KEY}\\{name}"))),
        };
        if service.is_driver || inp.deny.check_object(ObjectKind::Service, &facts).is_some() {
            continue;
        }
        let msi_row = inp.msi_services.iter().any(|s| prefix::eq_ci(s, name));
        let why = if how == Owned::InRoot && msi_row {
            ObjectWhy::MsiServiceRow
        } else {
            why_of(how)
        };
        objects.services.push(SysService {
            identity: service.identity.clone(),
            program: Some(program.clone()),
            why,
        });
    }

    'tasks: for task in &inp.index.tasks {
        let identity = &task.identity;
        // A COM handler that is not one of the app's classes runs somebody else's code.
        for action in &identity.actions {
            if let TaskAction::ComHandler { clsid, .. } = action {
                if !inp.clsids.iter().any(|c| prefix::eq_ci(c, clsid.trim())) {
                    continue 'tasks;
                }
            }
        }
        let programs = task_programs(identity, inp.env);
        let Some(files) = programs.files() else {
            continue;
        };
        // Every argument path of every action, checked with each program.
        let args: Vec<ProgramRef> = programs.all_arg_paths().cloned().collect();
        let mut how = Owned::InRoot;
        for file in &files {
            match owned(file, &args, inp) {
                None => continue 'tasks,
                Some(Owned::AppFile) => how = Owned::AppFile,
                Some(Owned::InRoot) => {}
            }
        }
        let in_baseline = inp
            .baseline
            .is_some_and(|b| b.has_key(&format!("{TASK_TREE}{}", identity.path)));
        for file in &files {
            let facts = ObjectGuardFacts {
                name_or_path_or_id: &identity.path,
                program: Some(file),
                in_baseline,
                ..ObjectGuardFacts::default()
            };
            if inp.deny.check_object(ObjectKind::Task, &facts).is_some() {
                continue 'tasks;
            }
        }
        objects.tasks.push(SysTask {
            identity: identity.clone(),
            program: files.first().map(|f| (*f).to_owned()),
            why: why_of(how),
        });
    }

    for rule in &inp.index.firewall {
        let ProgramRef::File(program) = &rule.program else {
            continue;
        };
        // A firewall rule's `App=` is a plain path: there are no arguments.
        let Some(how) = owned(program, &[], inp) else {
            continue;
        };
        let id = rule.identity.id.as_str();
        let embedded_resource = rule
            .fields
            .get("EmbedCtxt")
            .is_some_and(|c| c.trim_start().starts_with('@'));
        let facts = ObjectGuardFacts {
            name_or_path_or_id: id,
            program: Some(program),
            package_bound: rule.package_bound,
            resource_name: rule.resource_name || embedded_resource,
            in_baseline: inp
                .baseline
                .is_some_and(|b| b.has_value(FIREWALL_RULES_KEY, id)),
            ..ObjectGuardFacts::default()
        };
        if inp
            .deny
            .check_object(ObjectKind::FirewallRule, &facts)
            .is_some()
        {
            continue;
        }
        objects.firewall_rules.push(SysFirewallRule {
            identity: rule.identity.clone(),
            program: Some(program.clone()),
            why: why_of(how),
        });
    }

    objects
        .services
        .sort_by_key(|s| prefix::fold(&s.identity.name));
    objects
        .tasks
        .sort_by_key(|t| prefix::fold(&t.identity.path));
    objects
        .firewall_rules
        .sort_by(|a, b| a.identity.id.cmp(&b.identity.id));

    let total = objects.services.len() + objects.tasks.len() + objects.firewall_rules.len();
    if total > MAX_OBJECTS {
        let mut room = MAX_OBJECTS;
        let keep = |len: usize, room: &mut usize| {
            let n = len.min(*room);
            *room -= n;
            n
        };
        let services = keep(objects.services.len(), &mut room);
        let tasks = keep(objects.tasks.len(), &mut room);
        let rules = keep(objects.firewall_rules.len(), &mut room);
        objects.services.truncate(services);
        objects.tasks.truncate(tasks);
        objects.firewall_rules.truncate(rules);
        out.warnings.push(format!(
            "sysobj: {total} system objects are the app's, more than {MAX_OBJECTS}; the lists are cut \
             (services, then tasks, then firewall rules are kept)"
        ));
    }
    out
}
