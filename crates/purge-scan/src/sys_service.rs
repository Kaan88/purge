//! Scanner SYS-SERVICE (ENGINE_PLAN.md §5.6, §5.7.2): Windows services the removed app left behind.
//!
//! The scanner reads nothing itself. The services come from the system-object index the pipeline read
//! once for every scanner ([`ScanExt::sysobj`](crate::framework::ScanExt)), the harvest's record of the
//! app's services from the fingerprint (`fp.sys.services`), and the only other reads are the existence
//! of the service's program file and the volume it is on.
//!
//! # Which services are looked at
//!
//! A service is considered only when its program, resolved to one file
//! ([`ProgramRef::File`]: the `ServiceDll` of a `svchost.exe` service of the Windows directory, else the
//! file `ImagePath` runs), is the app's ([`ScanCtx::object_owner`]: inside an InstallRoot, or one of
//! the app's exe or outside-root files) and every absolute path among `ImagePath`'s arguments is a file
//! inside a root of the app or one of its files ([`arguments_are_the_apps`]; R2a S5:
//! `"C:\App\launcher.exe" C:\Other\svc.dll` runs another product's code), or when the harvest
//! recorded a service of that name. The service's name, display name and description are never a
//! reason.
//!
//! # What a candidate says
//!
//! `Target::Service { name }` (the key name as stored), `Action::DeleteKey`, `Category::System`, harm
//! Low, and the identity digest read now as `object_fp`. Then, in this order:
//!
//! 1. `DeleteFlag` already set: no candidate (Windows removes the service when its last handle closes).
//! 2. The guard's object rules (`DenyList::check_object`: drivers, per-user services, Windows' own
//!    services and programs, the baseline). A service hosted by svchost is judged by its host
//!    (`ServiceFacts::guard_program`), so `sys.service.windows` blocks it wherever its `ServiceDll`
//!    lies: it shares a Windows process and is never offered. A blocked service the harvest
//!    recorded is listed with that blocker (and `Driver` for a driver), so the user sees why it stays; a blocked service the harvest
//!    did not record is not listed at all.
//! 3. Recorded with an equal digest: `recorded_at_harvest`. Recorded with a different digest: the hard
//!    `ObjectChangedSinceHarvest` (something re-registered or edited the service after the harvest).
//!    Not recorded: the program alone speaks for it.
//! 4. `OwnedSystemObject` (Tier A, Object scope) only when the service was recorded with an equal
//!    digest, its program is still the app's and resolves to the file the harvest recorded, and that
//!    file is proven gone now ([`ScanCtx::program_gone`]: in an InstallRoot, the dangling rule's proof,
//!    the whole root gone on a fixed NTFS or ReFS volume with the serial the root recorded at harvest;
//!    elsewhere, absent on a fixed NTFS or ReFS volume). Otherwise `PointsIntoInstallRoot` only (Value
//!    scope, weight 6: at most Likely).
//! 5. A recorded service whose program does not resolve to one file now: the soft `ProgramUnresolved`.
//! 6. Any other service listing this one in `DependOnService`: the hard `HasDependents`, even when the
//!    dependent is the app's own (a second run removes it once the dependent is gone). While a service
//!    of the machine could not be read, the dependents are unknown and the service is blocked the same
//!    way, naming the unreadable services.
//! 7. An account that is not built in (`ServiceIdentity::account_builtin`): `Reversibility::Partial`
//!    and the soft `ReversibilityPartial` (the stored password does not come back on undo).
//! 8. The program inside another app's root, or one of its files: `InsideOtherApp` /
//!    `ReferencedByOtherApp`.
//!
//! The scanner does not know whether a service is running; the executor skips a running one (`InUse`).
//! The values under `Services\<name>` are not this scanner's (REF-ANY keeps them).

use purge_guard::deny::DenyList;
use purge_guard::prefix;
use purge_index::sysobj::{ProgramRef, ServiceFacts};
use purge_model::{
    Action, Blocker, Candidate, Category, Harm, ObjectWhy, Reversibility,
    SysService as ServiceRecord, Target,
};

use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};

/// The scanner's catalog id.
pub const ID: &str = "SYS-SERVICE";

/// What the scanner depends on: every service key and its `Parameters` subkey, read once per scan by
/// the system-object index (C-SYSOBJ), never by the scanner.
const ROOTS: &[RootSpec] = &[RootSpec::reg(
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    Some(2),
)];

/// The prefix of the index's error line for one service it could not read (`purge_index::sysobj`).
const UNREADABLE_SERVICE: &str = "sysobj: service ";

/// The prefix of the index's error line for a service list it could not read.
const LIST_UNREADABLE: &str = "sysobj: services:";

/// The SYS-SERVICE scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SysService;

impl Scanner for SysService {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
        let index = &ctx.ext.sysobj;
        let recorded_services = &ctx.fp.sys.services;
        // The list itself could not be read: the index's error is a scan warning; what it hides of the
        // app is said here.
        if index.errors.iter().any(|e| e.starts_with(LIST_UNREADABLE))
            && !recorded_services.is_empty()
        {
            ctx.ext.warn(
                ID,
                format!(
                    "the service list could not be read; the {} service(s) recorded at harvest are \
                     not offered",
                    recorded_services.len()
                ),
            );
        }
        if index.services.is_empty() {
            return Vec::new();
        }
        let deny = DenyList::compile(ctx.guard);
        let unreadable = unreadable_services(&index.errors);
        if !unreadable.is_empty() {
            ctx.ext.warn(
                ID,
                format!(
                    "{} service(s) could not be read ({}): which services depend on which is \
                     unknown, so every service offered is blocked (HasDependents)",
                    unreadable.len(),
                    unreadable.join(", ")
                ),
            );
        }
        for recorded in recorded_services {
            let name = recorded.identity.name.as_str();
            if unreadable.iter().any(|u| prefix::eq_ci(u, name)) {
                ctx.ext.warn(
                    ID,
                    format!("recorded service {name} could not be read now; it is not offered"),
                );
            }
        }
        let mut out: Vec<Candidate> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for facts in &index.services {
            let folded = prefix::fold(&facts.identity.name);
            if seen.contains(&folded) {
                continue;
            }
            if let Some(candidate) = service_candidate(ctx, &deny, facts, &unreadable) {
                seen.push(folded);
                out.push(candidate);
            }
        }
        out
    }
}

/// The candidate for one service, or `None` when the service is not offered or listed.
fn service_candidate(
    ctx: &ScanCtx<'_>,
    deny: &DenyList,
    facts: &ServiceFacts,
    unreadable: &[String],
) -> Option<Candidate> {
    let identity = &facts.identity;
    let name = identity.name.as_str();
    let recorded = recorded(ctx, name);
    let owner = ctx
        .object_owner(&facts.program)
        .filter(|_| arguments_are_the_apps(ctx, &facts.arg_paths));
    if owner.is_none() && recorded.is_none() {
        return None;
    }
    // Windows deletes it when its last handle closes; nothing is left to do.
    if facts.delete_flag {
        return None;
    }

    let program = facts.program.file();
    let now = identity.fp();
    let target = Target::Service {
        name: name.to_owned(),
    };
    // The guard's object rules with the facts the framework judges them from (R3a M5: one place).
    // `facts` is the index's first service of this name, which the framework looks up too.
    let denied = ctx.object_guard(deny, &target, Some(&now)).ok().flatten();
    if denied.is_some() && recorded.is_none() {
        return None;
    }

    let same_digest = recorded.is_some_and(|r| r.identity.fp() == now);

    let mut b = ctx.candidate(ID, target, Action::DeleteKey, Category::System);
    b = b.object_fp(now);
    b.harm(Harm::Low);

    if let Some(blocker) = denied {
        b.blocker(blocker);
        if facts.is_driver {
            b.blocker(Blocker::Driver);
        }
    }
    if recorded.is_some() && !same_digest {
        b.blocker(Blocker::ObjectChangedSinceHarvest);
    }

    // Evidence: the harvest's record of the object only when the program is proven gone.
    if let Some(owner) = owner {
        let gone = same_digest
            && recorded.is_some_and(|r| same_program(r, program))
            && program.is_some_and(|file| ctx.program_gone(file));
        match recorded {
            Some(r) if gone => b = b.owned_system_object(r.why, true),
            // Not proven gone: the program's word only, which the builder keeps at Tier B.
            _ => b = b.owned_system_object(owner, false),
        }
    } else if same_digest && let Some(r) = recorded {
        // The same service as recorded, but its program does not resolve now (the environment, for
        // instance): the record says whose it was, nothing says the program is gone.
        let why = match r.why {
            ObjectWhy::MsiServiceRow => ObjectWhy::ProgramInRoot,
            why => why,
        };
        b = b.owned_system_object(why, false);
    }
    if recorded.is_some() && !matches!(facts.program, ProgramRef::File(_)) {
        b.blocker(Blocker::ProgramUnresolved);
    }

    let mut dependents: Vec<String> = ctx
        .ext
        .sysobj
        .dependents_of(name)
        .into_iter()
        .filter(|d| !prefix::eq_ci(d, name))
        .map(str::to_owned)
        .collect();
    // A service the index could not read may depend on this one: unknown is never "none".
    for other in unreadable {
        if !prefix::eq_ci(other, name) && !dependents.iter().any(|d| prefix::eq_ci(d, other)) {
            dependents.push(other.clone());
        }
    }
    if !dependents.is_empty() {
        b.blocker(Blocker::HasDependents { names: dependents });
    }

    if !identity.account_builtin() {
        b.reversibility(Reversibility::Partial)
            .blocker(Blocker::ReversibilityPartial);
    }

    if let Some(file) = program {
        for blocker in ctx.other_apps.path_blockers(file) {
            if matches!(
                blocker,
                Blocker::InsideOtherApp { .. } | Blocker::ReferencedByOtherApp { .. }
            ) {
                b.blocker(blocker);
            }
        }
    }
    b.common_blockers();
    Some(b.build())
}

/// Whether every absolute path an object's command line names as an argument
/// (`purge_index::sysobj::argument_paths`) is a file of the app: inside one of its roots (any kind: an
/// argument in the app's own data folder is the app's) or one of its exe or outside-root files. An
/// argument that does not resolve to one local file is never the app's. True when there is none.
pub(crate) fn arguments_are_the_apps(ctx: &ScanCtx<'_>, args: &[ProgramRef]) -> bool {
    args.iter().all(|arg| match arg {
        ProgramRef::File(path) => {
            ctx.fp
                .roots
                .iter()
                .any(|r| !prefix::steps_back(path) && prefix::is_inside(path, &r.path))
                || ctx.is_app_file(path)
        }
        ProgramRef::Unresolved { .. } | ProgramRef::None => false,
    })
}

/// The harvest's record of the service `name` (compared ignoring case, as service names are).
fn recorded<'a>(ctx: &ScanCtx<'a>, name: &str) -> Option<&'a ServiceRecord> {
    let fp = ctx.fp;
    fp.sys
        .services
        .iter()
        .find(|s| prefix::eq_ci(&s.identity.name, name))
}

/// Whether the program resolved now is the file the harvest recorded for the service.
fn same_program(recorded: &ServiceRecord, now: Option<&str>) -> bool {
    match (recorded.program.as_deref(), now) {
        (Some(then), Some(now)) => prefix::is_same(then, now),
        _ => false,
    }
}

/// The names of the services the index could not read (its `sysobj: service <name>: ...` lines).
fn unreadable_services(errors: &[String]) -> Vec<String> {
    errors
        .iter()
        .filter_map(|line| {
            let rest = line.strip_prefix(UNREADABLE_SERVICE)?;
            let (name, _) = rest.split_once(": ")?;
            let name = name.trim();
            (!name.is_empty()).then(|| name.to_owned())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreadable_service_names_from_index_errors() {
        let errors = vec![
            "sysobj: service Bad One: ImagePath is not completely known".to_owned(),
            "sysobj: service X: Parameters\\ServiceDll: access denied".to_owned(),
            "sysobj: services: not captured".to_owned(),
            "sysobj: firewall rule {1}: Empty".to_owned(),
            "sysobj: environment: not captured".to_owned(),
        ];
        assert_eq!(unreadable_services(&errors), ["Bad One", "X"]);
    }

    #[test]
    fn roots_are_well_formed() {
        assert!(ROOTS.iter().all(RootSpec::is_well_formed));
    }
}
