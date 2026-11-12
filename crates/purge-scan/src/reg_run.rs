//! REG-RUN (ENGINE_PLAN.md §5.6): `Run` / `RunOnce` values and the `StartupApproved` value that goes
//! with them.
//!
//! Value targets only: the `Run`, `RunOnce` and `StartupApproved\*` keys are structural containers
//! shared by every app that starts with Windows.
//!
//! # What is offered
//!
//! - A `Run` or `RunOnce` value (64-bit and 32-bit view, `HKLM` and `HKU\<SID>`) whose command leads
//!   into the app: `PointsIntoInstallRoot` for a command at or under an InstallRoot or naming a file of
//!   the exe set, `DanglingRef` when that file is proven gone, `InPreUninstallRefSnapshot` and
//!   `InstallerManifest` when the fingerprint has the record.
//! - The value of the same name in `StartupApproved\Run` (for a 64-bit `Run` value) or
//!   `StartupApproved\Run32` (for a 32-bit one) of the same hive: Explorer's enabled/disabled switch
//!   for exactly that `Run` value. It holds a binary state and no reference, so it is attributed
//!   through the `Run` value: `ChainedRef` with that value's tier, plus `PointsIntoInstallRoot` /
//!   `DanglingRef` for the command its name stands for. When the uninstaller already removed the `Run`
//!   value, the harvested Run entry (`Anchors::run_entries`) stands in for it.
//! - A `StartupApproved\StartupFolder` value: the switch of a shortcut in the Startup folder of the
//!   same scope. It is offered when that shortcut still exists and its target leads into the app
//!   (`ChainedRef` to the shortcut, plus the reference evidence of its target).

use purge_guard::prefix;
use purge_index::matcher::RefMatch;
use purge_model::{Action, Candidate, Category, Target, Tier};
use purge_source::types::SourceError;

use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};
use crate::reg_software::common::{self, Foreign};

/// The scanner's catalog id.
pub const ID: &str = "REG-RUN";

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[
    RootSpec::reg(r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Some(0)),
    RootSpec::reg(
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        Some(0),
    ),
    RootSpec::reg(
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved",
        Some(1),
    ),
];

/// The keys the scanner reads single values from (entries of
/// `purge_guard::containers::VALUE_CONTAINERS`).
const VALUE_CONTAINERS: &[&str] = &[
    r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\*",
];

/// The Startup folder below a Start Menu root.
const STARTUP_TAIL: &str = r"Microsoft\Windows\Start Menu\Programs\Startup";

/// The REG-RUN scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegRun;

impl Scanner for RegRun {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn value_containers(&self) -> &[&'static str] {
        VALUE_CONTAINERS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, app: &AppIdentityView) -> Vec<Candidate> {
        let mut out = Vec::new();
        common::for_each_app(ctx, app, |ctx, app| scan_app(ctx, app, &mut out));
        common::dedupe(out)
    }
}

fn scan_app(ctx: &ScanCtx<'_>, app: &AppIdentityView, out: &mut Vec<Candidate>) {
    let foreign = Foreign::new(ctx);
    for base in common::software_bases(ctx) {
        let wow = common::is_wow(&base);
        let native = if wow {
            prefix::parent(&base).unwrap_or(&base)
        } else {
            &base
        };
        let approved_dir = format!(
            r"{native}\{}\Explorer\StartupApproved",
            common::CURRENT_VERSION
        );
        let lists = [
            ("Run", Some(if wow { "Run32" } else { "Run" })),
            ("RunOnce", None),
        ];
        for (list, approved) in lists {
            let run_key = format!(r"{base}\{}\{list}", common::CURRENT_VERSION);
            let approved_key = approved.map(|name| format!(r"{approved_dir}\{name}"));
            run_list(ctx, app, &foreign, &run_key, approved_key.as_deref(), out);
        }
        if !wow {
            startup_folder(
                ctx,
                app,
                native,
                &format!(r"{approved_dir}\StartupFolder"),
                out,
            );
        }
    }
}

/// The values of one `Run` / `RunOnce` key, and the `StartupApproved` values that go with them.
fn run_list(
    ctx: &ScanCtx<'_>,
    app: &AppIdentityView,
    foreign: &Foreign,
    run_key: &str,
    approved_key: Option<&str>,
    out: &mut Vec<Candidate>,
) {
    let values = match ctx.reg.values(run_key) {
        Ok(values) => values,
        // No key: every harvested entry of it is gone.
        Err(SourceError::NotFound) => Vec::new(),
        Err(_) => return,
    };
    for value in &values {
        let Some(command) = value.data.string().filter(|_| value.data.is_complete()) else {
            continue;
        };
        let matches = app.refs.find_all(&command);
        if matches.is_empty() {
            continue;
        }
        let mut b = ctx.candidate(
            ID,
            Target::RegValue {
                path: run_key.to_owned(),
                name: value.name.clone(),
            },
            Action::DeleteValue,
            Category::Startup,
        );
        // A command that names another app as well (that app's launcher with a file of this app as
        // an argument) is not this app's entry: it is listed, blocked, and its switch is left alone.
        let other = foreign
            .in_text(&app.refs, &value.name)
            .or_else(|| foreign.in_text(&app.refs, &command));
        let shared = other.is_some();
        if !common::add_value_evidence(ctx, &mut b, &matches, other) {
            continue;
        }
        let tier = if b
            .evidence()
            .iter()
            .any(|e| e.tier == Tier::A && e.weight > 0)
        {
            Tier::A
        } else {
            Tier::B
        };
        out.push(b.build());
        if let (Some(approved_key), false) = (approved_key, shared) {
            approval(ctx, approved_key, &value.name, run_key, tier, &matches, out);
        }
    }
    // Entries recorded at harvest whose Run value the uninstaller removed: the switch may remain.
    let Some(approved_key) = approved_key else {
        return;
    };
    for entry in &ctx.fp.anchors.run_entries {
        let gone = !values.iter().any(|v| prefix::eq_ci(&v.name, &entry.name));
        if gone && ctx.same_key(&entry.key, run_key) {
            let matches = app.refs.find_all(&entry.data);
            approval(
                ctx,
                approved_key,
                &entry.name,
                run_key,
                Tier::A,
                &matches,
                out,
            );
        }
    }
}

/// The `StartupApproved` value named `name`, attributed through the `Run` value it switches.
fn approval(
    ctx: &ScanCtx<'_>,
    approved_key: &str,
    name: &str,
    run_key: &str,
    tier: Tier,
    matches: &[RefMatch],
    out: &mut Vec<Candidate>,
) {
    if ctx.reg.value(approved_key, name).is_err() {
        return;
    }
    let mut b = ctx.candidate(
        ID,
        Target::RegValue {
            path: approved_key.to_owned(),
            name: name.to_owned(),
        },
        Action::DeleteValue,
        Category::Startup,
    );
    if !b.chained_ref(tier, &format!("{run_key}|{name}")) {
        return;
    }
    add_path_evidence(ctx, &mut b, matches);
    b.common_blockers();
    out.push(b.build());
}

/// `PointsIntoInstallRoot` and `DanglingRef` for the paths among `matches`.
fn add_path_evidence(
    ctx: &ScanCtx<'_>,
    b: &mut crate::framework::CandidateBuilder<'_>,
    matches: &[RefMatch],
) -> bool {
    let mut any = false;
    for path in matches
        .iter()
        .filter(|m| !m.name_only)
        .filter_map(|m| m.path.as_deref())
    {
        any |= b.points_into_install_root(path);
        if let Some(dangling) = ctx.dangling(path) {
            any |= b.dangling_ref(&dangling);
        }
    }
    any
}

/// The values of `StartupApproved\StartupFolder` whose shortcut, in the Startup folder of the same
/// scope, leads into the app.
fn startup_folder(
    ctx: &ScanCtx<'_>,
    app: &AppIdentityView,
    software: &str,
    approved_key: &str,
    out: &mut Vec<Candidate>,
) {
    let Ok(values) = ctx.reg.values(approved_key) else {
        return;
    };
    // `HKU\<SID>\Software` switches the user's Startup folder, `HKLM\SOFTWARE` the all-users one.
    let sid = prefix::segments(software)
        .nth(1)
        .filter(|_| !prefix::eq_ci(prefix::segments(software).next().unwrap_or(""), "HKLM"));
    let folder = match sid {
        Some(sid) => match ctx.guard.profile(sid) {
            Some(profile) => format!(r"{}\{STARTUP_TAIL}", profile.appdata),
            None => return,
        },
        None => format!(r"{}\{STARTUP_TAIL}", ctx.guard.program_data),
    };
    for value in &values {
        if value.name.is_empty() || value.name.contains(['\\', '/']) {
            continue;
        }
        let shortcut = format!(r"{folder}\{}", value.name);
        let Ok(link) = ctx.fs.read_shortcut(&shortcut) else {
            continue;
        };
        let matches: Vec<RefMatch> = [link.raw_path, link.workdir]
            .into_iter()
            .flatten()
            .flat_map(|s| app.refs.find_all(&s))
            .collect();
        let mut b = ctx.candidate(
            ID,
            Target::RegValue {
                path: approved_key.to_owned(),
                name: value.name.clone(),
            },
            Action::DeleteValue,
            Category::Startup,
        );
        if add_path_evidence(ctx, &mut b, &matches) && b.chained_ref(Tier::A, &shortcut) {
            b.common_blockers();
            out.push(b.build());
        }
    }
}
