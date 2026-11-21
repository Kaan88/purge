//! The real [`ExecBackend`] of `plan.execute`: `purge-exec` over the broker's own store and the live
//! machine (M3-EXEC). The wiring is the rig CLI's `exec` verb (`bins/purge-engine/src/cli/exec.rs`),
//! through the one home the broker has for it ([`crate::live_host`]): the deny-list of the live
//! machine, the backends of services, tasks and firewall rules, Restart Manager (query only), the
//! boot-time move list and System Restore.
//!
//! The rules (what the dialog shows, that the run is that very plan, what every refusal answers) are
//! in [`crate::execute`]; this file only runs. It is not exercised by the library tests, which need a
//! real store (the executor's `test-support` feature, which the broker does not have): `purge-exec`'s
//! tests cover `execute_bound` on real stores, the handler's tests script this trait, and the elevated
//! end-to-end run is VM work.

use std::collections::BTreeSet;

use purge_engine::pipeline::{self, Sources};
use purge_exec::act_typed::WinPackages;
use purge_exec::execute::{ExecEnv, ExecOutput, Progress, execute_bound};
use purge_exec::locked::SystemPendingRenames;
use purge_exec::plan_in::GoneLists;
use purge_exec::prepare::{RestartManager, SystemRestore};
use purge_exec::storage::StorageRoots;
use purge_model::{FileTime, ProgramId};
use purge_source::live::Live;

use crate::execute::{ExecBackend, ExecFailure, ExecJob};
use crate::live_host::{LiveObjects, live_deny_list};

/// The executor over the store at `roots`. `purge_dirs` are Purge's own directories (the broker's
/// engine settings): the guard protects them and the data root.
pub struct LiveExec {
    roots: StorageRoots,
    purge_dirs: Vec<String>,
}

impl LiveExec {
    /// The executor over `roots`.
    pub fn new(roots: StorageRoots, purge_dirs: Vec<String>) -> Self {
        Self { roots, purge_dirs }
    }
}

impl ExecBackend for LiveExec {
    fn now(&self) -> FileTime {
        crate::purge::system_now()
    }

    fn execute(
        &self,
        job: ExecJob,
        progress: &dyn Fn(&Progress<'_>),
    ) -> Result<ExecOutput, ExecFailure> {
        let live = Live::new();
        let sources = Sources {
            reg: &live.registry,
            fs: &live.fs,
            sys: &live.system,
        };
        // The owners of the plan's items are left out of the other apps' roots, as the CLI does.
        let scan = job.plan.scan();
        let owners: Vec<ProgramId> = scan
            .items
            .iter()
            .chain(&scan.absorbed)
            .map(|candidate| candidate.owner.program_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let (deny, _warnings) =
            live_deny_list(sources, self.roots.data_root(), &self.purge_dirs, &owners)
                .map_err(|why| ExecFailure::Machine(format!("{why}; nothing was done")))?;
        // The M1b exemption lists are judged now over a fresh inventory, never taken from the plan.
        let inventory = pipeline::inventory(sources);
        let lists = pipeline::m1b_lists(sources, &job.fingerprint, &inventory);
        let mut settings = job.settings;
        settings.gone = GoneLists::from_decide(&lists);

        let objects = LiveObjects::new(sources);
        let packages = WinPackages::new();
        let lockers = RestartManager;
        let mut pending = SystemPendingRenames;
        let mut env = ExecEnv::new(&self.roots, &deny, &packages, &lockers, &mut pending);
        env.objects = Some(objects.backends());
        env.progress = Some(progress);
        execute_bound(job.plan, settings, &job.fingerprint, env, SystemRestore)
            .map_err(|e| ExecFailure::Exec(Box::new(e)))
    }
}
