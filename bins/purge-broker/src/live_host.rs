//! What an executor call needs from the live machine besides the store: the guard's deny-list and the
//! backends of services, scheduled tasks and firewall rules (M3-UNDO; the same wiring as the
//! `rig-exec` CLI's `exec` verbs, which build them inline).

use std::collections::BTreeMap;
use std::path::Path;

use purge_exec::act_firewall::LiveFirewall;
use purge_exec::act_service::LiveServices;
use purge_exec::act_task::WinTasks;
use purge_exec::execute::ObjectBackends;
use purge_guard::canon::OtherAppRoot;
use purge_guard::deny::DenyList;
use purge_harvest::roots::guard_env;
use purge_model::ProgramId;
use purge_win::env::EnvMap;

use purge_engine::pipeline::{self, Sources};

/// The deny-list of the live machine, as the scan builds it: the guard facts, Purge's own directories
/// (`purge_dirs`) with the store's `data_root`, and the roots of every installed app except those of
/// `exclude` (the owners of the plan or session). Returns it with the warnings the sources gave.
///
/// # Errors
///
/// The reason when the deny-list is invalid or the data root has no canonical path (so the guard could
/// not protect it): nothing may then be done.
pub fn live_deny_list(
    sources: Sources<'_>,
    data_root: &Path,
    purge_dirs: &[String],
    exclude: &[ProgramId],
) -> Result<(DenyList, Vec<String>), String> {
    let mut warnings: Vec<String> = Vec::new();
    let vars = sources.sys.env().unwrap_or_else(|e| {
        warnings.push(format!("guard: the environment could not be read ({e})"));
        BTreeMap::new()
    });
    let env_map: EnvMap = vars.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let (mut guard, guard_warnings) = guard_env(sources.reg, sources.sys);
    warnings.extend(guard_warnings.into_iter().map(|w| format!("guard: {w}")));
    let data_root = data_root.to_string_lossy().into_owned();
    let mut dirs = purge_dirs.to_vec();
    dirs.push(data_root.clone());
    guard.purge_dirs = pipeline::canonical_dirs(&dirs, &guard, &mut warnings);
    let inventory = pipeline::inventory(sources);
    let excluded: Vec<&ProgramId> = exclude.iter().collect();
    let base = DenyList::compile(&guard);
    let others = pipeline::other_apps(&inventory.doc.entries, &excluded, &env_map, &guard, &base);
    guard.other_app_roots = others
        .iter()
        .flat_map(|app| {
            app.roots.iter().map(|root| OtherAppRoot {
                app: app.name.clone(),
                path: root.clone(),
            })
        })
        .collect();
    let deny = DenyList::compile(&guard);
    if let Some(why) = deny.invalid() {
        return Err(format!("the deny-list could not be built ({why})"));
    }
    let canonical_root =
        pipeline::canonical_dirs(std::slice::from_ref(&data_root), &guard, &mut Vec::new());
    if canonical_root.is_empty() {
        return Err(format!(
            "the store's data root {data_root} has no canonical path, so the guard could not protect it"
        ));
    }
    Ok((deny, warnings))
}

/// The live backends of services, scheduled tasks and firewall rules.
pub struct LiveObjects {
    services: LiveServices,
    tasks: WinTasks,
    firewall: LiveFirewall,
}

impl LiveObjects {
    /// The backends; the task files' directory comes from the machine's own layout.
    pub fn new(sources: Sources<'_>) -> LiveObjects {
        LiveObjects {
            services: LiveServices,
            tasks: WinTasks::from_env(&guard_env(sources.reg, sources.sys).0),
            firewall: LiveFirewall,
        }
    }

    /// The backends as the executor takes them.
    pub fn backends(&self) -> ObjectBackends<'_> {
        ObjectBackends {
            services: &self.services,
            tasks: &self.tasks,
            firewall: &self.firewall,
        }
    }
}
