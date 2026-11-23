//! Command-line parsing: the verb (and sub-verb), then the arguments of each implemented verb
//! (ENGINE_PLAN.md §3.4).
//!
//! Options are `--name value` or `--name=value`; `-o` is the short form of `--out`. An option given twice,
//! an unknown option, a missing value and a missing or extra positional argument are usage errors (exit
//! code 2). `quarantine purge` takes lists: `--ids` and `--confirm-user-data` take every following
//! argument up to the next option. Verbs of later milestones are recognised, their arguments are not
//! interpreted, and they report "not implemented" (exit code 1).
//!
//! The executor verbs (`exec`, `undo`, `journal`, `quarantine`, `plan from-targets`) are parsed in every
//! build, so a usage error is reported the same way everywhere; only a `rig-exec` build runs them
//! ([`crate::cli`]).

use std::path::PathBuf;

use purge_model::ScanMode;

/// The usage text printed by `--help` and after a usage error.
pub const USAGE: &str = "\
usage: purge-engine <verb> [args]

modes:
  --stdio                                   serve the UI over stdin/stdout (medium integrity)

verbs:
  inventory [--json] [-o <inv.json>]
  harvest <program_id> [-o <fp.json>]
  uninstall <program_id> --quiet [--fp <fp.json>] [-o <run.json>]
  scan --fp <fp.json> [--mode post|external|forced] [--app <id>] -o <plan.json>
  scan --path <dir> [--app <id>] -o <plan.json>
  plan show <plan.json>
  baseline build --out <file>               build this Windows' local baseline (writes only <file>)
  baseline info <file>                      check a local baseline file and print its seal
  hello                                     print what engine.hello reports, as JSON: the engine, this
                                            Windows, and the baseline view a scan would work with
  walk-floor [--runs <n>] [-o <floor.json>] time a bare read of the registry scope a harvest walks:
                                            every key entered, its values read, nothing tested or
                                            changed (the VM rig holds the harvest's time against it)
  kb lint <pack.json>... [--baselines <dir>]

  <program_id> is an inventory id (HKLM|64|Git_is1) or the Uninstall key name of exactly one entry.
  scan also writes the sidecar <plan>.scan.json next to the plan.
  -o never writes through a junction, symbolic link or mount point anywhere on its path.

executor verbs (headless, without the consent dialog: only a rig-exec build of the VM rig runs them;
a normal build refuses them with exit code 5):
  exec --plan <plan.json> --confirm <hash> [--select <ids.json>] [--allow-irreversible]
       [--restore-point off|high-risk|always] [--fp <fingerprint.json>] [-o <report.json>]
       --fp gives the app's roots and gone installer records: without it no service, scheduled
       task or firewall rule is deleted.
  undo --session <id> [--items <ids.json>] [--confirm <plan_hash>] [-o <undo.json>]
  journal recover
  journal resume [--session <id>]
  journal rollback [--session <id>]
  journal show --session <id>
  journal fault-points
  journal retry-held --session <id>
  quarantine expiring
  quarantine purge --ids <session/op>... --yes-irreversible [--confirm-user-data <session/op>...]
  plan from-targets <targets.json> -o <plan.json>      test tool of the VM rig

  exec reads the sidecar <plan>.scan.json; <hash> is the confirm hash of the plan and the selection.
  <ids.json> is a JSON array of candidate ids (or {\"ids\": [...]}); without --select the plan's
  preselected items run. Elevation is needed by exec, undo, journal resume / rollback / retry-held
  and quarantine purge. A user-data item is purged only when --confirm-user-data names it too.
  journal retry-held tries the held (in-use) items of a finished session again.

exit codes:
   0  ok
   1  not implemented yet
   2  usage error or broken precondition
   3  runtime error
   4  uninstall failed, cancelled or timed out
   5  needs the consent dialog (executor verbs of a normal build)
   6  plan refused: hash, selection, order or confirmation; nothing was done
   7  needs elevation
   8  needs recovery first: an interrupted session is pending (journal recover)
   9  store or journal integrity failure
  10  partial: not every item ended done (the document is still written)
  11  undo ended with conflicts or failures (the document is still written)
  12  session not closed, or its report or index entry not written (the document is still written; takes precedence over 10 and 11, which stderr then names)

  --version, -V                             print the version
  --help, -h                                print this help
";

/// A recognised top-level command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `--stdio`.
    Stdio,
    /// `inventory`.
    Inventory,
    /// `harvest`.
    Harvest,
    /// `uninstall`.
    Uninstall,
    /// `scan`.
    Scan,
    /// `plan show`.
    PlanShow,
    /// `exec`.
    Exec,
    /// `undo`.
    Undo,
    /// `journal recover`.
    JournalRecover,
    /// `journal resume`.
    JournalResume,
    /// `journal rollback`.
    JournalRollback,
    /// `journal show`.
    JournalShow,
    /// `journal fault-points`.
    JournalFaultPoints,
    /// `journal retry-held`.
    JournalRetryHeld,
    /// `quarantine expiring`.
    QuarantineExpiring,
    /// `quarantine purge`.
    QuarantinePurge,
    /// `plan from-targets` (a test tool of the VM rig).
    PlanFromTargets,
    /// `baseline build`.
    BaselineBuild,
    /// `baseline info`.
    BaselineInfo,
    /// `hello`.
    Hello,
    /// `walk-floor`.
    WalkFloor,
    /// `kb lint`.
    KbLint,
}

impl Command {
    /// The command as typed.
    pub fn name(self) -> &'static str {
        match self {
            Command::Stdio => "--stdio",
            Command::Inventory => "inventory",
            Command::Harvest => "harvest",
            Command::Uninstall => "uninstall",
            Command::Scan => "scan",
            Command::PlanShow => "plan show",
            Command::Exec => "exec",
            Command::Undo => "undo",
            Command::JournalRecover => "journal recover",
            Command::JournalResume => "journal resume",
            Command::JournalRollback => "journal rollback",
            Command::JournalShow => "journal show",
            Command::JournalFaultPoints => "journal fault-points",
            Command::JournalRetryHeld => "journal retry-held",
            Command::QuarantineExpiring => "quarantine expiring",
            Command::QuarantinePurge => "quarantine purge",
            Command::PlanFromTargets => "plan from-targets",
            Command::BaselineBuild => "baseline build",
            Command::BaselineInfo => "baseline info",
            Command::Hello => "hello",
            Command::WalkFloor => "walk-floor",
            Command::KbLint => "kb lint",
        }
    }

    /// The milestone that implements the command (ENGINE_PLAN.md §11.1).
    pub fn milestone(self) -> &'static str {
        match self {
            Command::Inventory
            | Command::Harvest
            | Command::Uninstall
            | Command::Scan
            | Command::PlanShow => "M1a",
            Command::Exec
            | Command::Undo
            | Command::JournalRecover
            | Command::JournalResume
            | Command::JournalRollback
            | Command::JournalShow
            | Command::JournalFaultPoints
            | Command::JournalRetryHeld
            | Command::QuarantineExpiring
            | Command::QuarantinePurge
            | Command::PlanFromTargets => "M2",
            Command::BaselineBuild | Command::BaselineInfo | Command::Hello => "BL",
            Command::KbLint => "M4",
            Command::Stdio | Command::WalkFloor => "M3",
        }
    }

    /// Whether the command is a test tool of the VM rig rather than a verb of the product
    /// (`plan from-targets`, `journal fault-points`).
    pub fn is_rig_tool(self) -> bool {
        matches!(self, Command::PlanFromTargets | Command::JournalFaultPoints)
    }
}

/// `--restore-point off|high-risk|always`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RestorePointArg {
    /// `off`: never.
    Off,
    /// `high-risk`: only for a high-risk run (the default).
    #[default]
    HighRisk,
    /// `always`: for every run.
    Always,
}

/// `plan from-targets <targets.json> -o <plan.json>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromTargetsArgs {
    /// The `purge.rig.targets/0` document.
    pub targets: PathBuf,
    /// The plan file; the sidecar goes next to it.
    pub out: PathBuf,
}

/// `exec --plan <plan.json> --confirm <hash> [--select <ids.json>] [--allow-irreversible]
/// [--restore-point m] [--fp <fingerprint.json>] [-o <report.json>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecArgs {
    /// The plan file; its sidecar is read next to it.
    pub plan: PathBuf,
    /// The confirm hash of the plan and the selection.
    pub confirm: String,
    /// The selected candidate ids; the plan's preselected items when absent.
    pub select: Option<PathBuf>,
    /// The user acknowledged that removals without an undo are final.
    pub allow_irreversible: bool,
    /// When to ask for a restore point.
    pub restore_point: RestorePointArg,
    /// The app's fingerprint (`purge.fp/0`, harvest's output): the run's program roots and its M1b
    /// exemption lists come from it. Without it, no object is deleted and those exemptions stay closed.
    pub fp: Option<PathBuf>,
    /// Where the `purge.exec/1` report goes besides stdout.
    pub out: Option<PathBuf>,
}

/// `undo --session <id> [--items <ids.json>] [--confirm <plan_hash>] [-o <undo.json>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoArgs {
    /// The session id.
    pub session: String,
    /// The candidate ids to undo; every op of the session when absent.
    pub items: Option<PathBuf>,
    /// The plan hash the caller confirmed; it must be the session's.
    pub confirm: Option<String>,
    /// Where the `purge.undo/1` report goes besides stdout.
    pub out: Option<PathBuf>,
}

/// `quarantine purge --ids <id>... --yes-irreversible [--confirm-user-data <id>...]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeArgs {
    /// The `session/op` ids to purge, as `quarantine expiring` lists them.
    pub ids: Vec<String>,
    /// The ids among `ids` that are user data, confirmed one by one.
    pub confirm_user_data: Vec<String>,
}

/// An executor verb and its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecVerb {
    /// `plan from-targets`.
    PlanFromTargets(FromTargetsArgs),
    /// `exec`.
    Exec(ExecArgs),
    /// `undo`.
    Undo(UndoArgs),
    /// `journal recover`.
    JournalRecover,
    /// `journal resume [--session <id>]`; every pending session when absent.
    JournalResume(Option<String>),
    /// `journal rollback [--session <id>]`; every pending session when absent.
    JournalRollback(Option<String>),
    /// `journal show --session <id>`.
    JournalShow(String),
    /// `journal fault-points`.
    JournalFaultPoints,
    /// `journal retry-held --session <id>`.
    JournalRetryHeld(String),
    /// `quarantine expiring`.
    QuarantineExpiring,
    /// `quarantine purge`.
    QuarantinePurge(PurgeArgs),
}

impl ExecVerb {
    /// The command of the verb.
    pub fn command(&self) -> Command {
        match self {
            ExecVerb::PlanFromTargets(_) => Command::PlanFromTargets,
            ExecVerb::Exec(_) => Command::Exec,
            ExecVerb::Undo(_) => Command::Undo,
            ExecVerb::JournalRecover => Command::JournalRecover,
            ExecVerb::JournalResume(_) => Command::JournalResume,
            ExecVerb::JournalRollback(_) => Command::JournalRollback,
            ExecVerb::JournalShow(_) => Command::JournalShow,
            ExecVerb::JournalFaultPoints => Command::JournalFaultPoints,
            ExecVerb::JournalRetryHeld(_) => Command::JournalRetryHeld,
            ExecVerb::QuarantineExpiring => Command::QuarantineExpiring,
            ExecVerb::QuarantinePurge(_) => Command::QuarantinePurge,
        }
    }
}

/// `inventory [--json] [-o <file>]`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InventoryArgs {
    /// Print the `purge.inventory/0` document instead of a table.
    pub json: bool,
    /// Write the document to this file instead of stdout.
    pub out: Option<PathBuf>,
}

/// `harvest <program_id> [-o <fp.json>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarvestArgs {
    /// The entry to harvest.
    pub program_id: String,
    /// Where the fingerprint goes; stdout when absent.
    pub out: Option<PathBuf>,
}

/// `uninstall <program_id> --quiet [--fp <fp.json>] [-o <run.json>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallArgs {
    /// The entry to uninstall.
    pub program_id: String,
    /// The fingerprint to use and update in place.
    pub fp: Option<PathBuf>,
    /// Where the `purge.run/0` document goes; stdout when absent.
    pub out: Option<PathBuf>,
}

/// What a scan starts from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanFrom {
    /// A fingerprint and a mode (`--fp`, `--mode`, default `post`).
    Fingerprint {
        /// The fingerprint file.
        fp: PathBuf,
        /// The scan mode.
        mode: ScanMode,
    },
    /// A portable app's directory (`--path`), always scanned in `forced` mode.
    Path(String),
}

/// `scan (--fp <fp.json> [--mode m] | --path <dir>) [--app <id>] -o <plan.json>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanArgs {
    /// What the scan starts from.
    pub from: ScanFrom,
    /// The plan's `app` field.
    pub app: Option<String>,
    /// The plan file; the sidecar goes next to it.
    pub out: PathBuf,
}

/// `baseline build --out <file>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineBuildArgs {
    /// The local baseline file to write (the only file the verb writes).
    pub out: PathBuf,
}

/// `baseline info <file>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineInfoArgs {
    /// The local baseline file to read.
    pub file: PathBuf,
}

/// `walk-floor [--runs <n>] [-o <floor.json>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkFloorArgs {
    /// How many times the scope is walked ([`WALK_FLOOR_RUNS`] by default).
    pub runs: u32,
    /// Where the document goes; stdout when `None`.
    pub out: Option<PathBuf>,
}

/// The walks of one `walk-floor` call when `--runs` is not given.
pub const WALK_FLOOR_RUNS: u32 = 3;

/// The most walks one `walk-floor` call makes.
pub const WALK_FLOOR_MAX_RUNS: u32 = 20;

/// `plan show <plan.json>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanShowArgs {
    /// The plan file.
    pub plan: PathBuf,
}

/// The result of parsing the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    /// `--version`.
    Version,
    /// `--help`.
    Help,
    /// A command of a later milestone, with its arguments (not interpreted).
    NotImplemented(Command, Vec<String>),
    /// `--stdio`.
    Stdio,
    /// `inventory`.
    Inventory(InventoryArgs),
    /// `harvest`.
    Harvest(HarvestArgs),
    /// `uninstall`.
    Uninstall(UninstallArgs),
    /// `scan`.
    Scan(ScanArgs),
    /// `plan show`.
    PlanShow(PlanShowArgs),
    /// `baseline build`.
    BaselineBuild(BaselineBuildArgs),
    /// `baseline info`.
    BaselineInfo(BaselineInfoArgs),
    /// `hello`.
    Hello,
    /// `walk-floor`.
    WalkFloor(WalkFloorArgs),
    /// An executor verb (run only by a `rig-exec` build).
    Executor(ExecVerb),
}

/// Parses a command line (without the program name).
///
/// # Errors
///
/// A one-line description of the usage error.
pub fn parse(args: &[String]) -> Result<Invocation, String> {
    let (cmd, rest) = match verb(args)? {
        Verb::Version => return Ok(Invocation::Version),
        Verb::Help => return Ok(Invocation::Help),
        Verb::Run(cmd, rest) => (cmd, rest),
    };
    match cmd {
        Command::Stdio => no_arguments("--stdio", &rest).map(|()| Invocation::Stdio),
        Command::Inventory => inventory(&rest).map(Invocation::Inventory),
        Command::Harvest => harvest(&rest).map(Invocation::Harvest),
        Command::Uninstall => uninstall(&rest).map(Invocation::Uninstall),
        Command::Scan => scan(&rest).map(Invocation::Scan),
        Command::PlanShow => plan_show(&rest).map(Invocation::PlanShow),
        Command::BaselineBuild => baseline_build(&rest).map(Invocation::BaselineBuild),
        Command::BaselineInfo => baseline_info(&rest).map(Invocation::BaselineInfo),
        Command::Hello => no_arguments("hello", &rest).map(|()| Invocation::Hello),
        Command::WalkFloor => walk_floor(&rest).map(Invocation::WalkFloor),
        Command::PlanFromTargets => from_targets(&rest)
            .map(ExecVerb::PlanFromTargets)
            .map(Invocation::Executor),
        Command::Exec => exec(&rest).map(ExecVerb::Exec).map(Invocation::Executor),
        Command::Undo => undo(&rest).map(ExecVerb::Undo).map(Invocation::Executor),
        Command::JournalRecover => no_arguments("journal recover", &rest)
            .map(|()| Invocation::Executor(ExecVerb::JournalRecover)),
        Command::JournalResume => optional_session("journal resume", &rest)
            .map(ExecVerb::JournalResume)
            .map(Invocation::Executor),
        Command::JournalRollback => optional_session("journal rollback", &rest)
            .map(ExecVerb::JournalRollback)
            .map(Invocation::Executor),
        Command::JournalShow => optional_session("journal show", &rest)?
            .ok_or_else(|| "journal show: needs --session <id>".to_owned())
            .map(ExecVerb::JournalShow)
            .map(Invocation::Executor),
        Command::JournalFaultPoints => no_arguments("journal fault-points", &rest)
            .map(|()| Invocation::Executor(ExecVerb::JournalFaultPoints)),
        Command::JournalRetryHeld => optional_session("journal retry-held", &rest)?
            .ok_or_else(|| "journal retry-held: needs --session <id>".to_owned())
            .map(ExecVerb::JournalRetryHeld)
            .map(Invocation::Executor),
        Command::QuarantineExpiring => no_arguments("quarantine expiring", &rest)
            .map(|()| Invocation::Executor(ExecVerb::QuarantineExpiring)),
        Command::QuarantinePurge => quarantine_purge(&rest)
            .map(ExecVerb::QuarantinePurge)
            .map(Invocation::Executor),
        Command::KbLint => Ok(Invocation::NotImplemented(Command::KbLint, rest)),
    }
}

/// The first word of a command line.
enum Verb {
    Version,
    Help,
    /// A command and the arguments after its verb (and sub-verb).
    Run(Command, Vec<String>),
}

/// Recognises the verb (and sub-verb).
fn verb(args: &[String]) -> Result<Verb, String> {
    let Some(first) = args.first() else {
        return Err("missing verb".into());
    };
    let rest = |n: usize| args[n..].to_vec();
    let sub = |verb: &str, choices: &[(&str, Command)]| {
        let Some(s) = args.get(1) else {
            return Err(format!("'{verb}' needs a sub-verb"));
        };
        choices
            .iter()
            .find(|(name, _)| name == s)
            .map(|&(_, cmd)| Verb::Run(cmd, rest(2)))
            .ok_or_else(|| format!("unknown '{verb}' sub-verb '{s}'"))
    };
    let cmd = match first.as_str() {
        "--version" | "-V" => return Ok(Verb::Version),
        "--help" | "-h" | "help" => return Ok(Verb::Help),
        "--stdio" => Command::Stdio,
        "inventory" => Command::Inventory,
        "harvest" => Command::Harvest,
        "uninstall" => Command::Uninstall,
        "scan" => Command::Scan,
        "hello" => Command::Hello,
        "walk-floor" => Command::WalkFloor,
        "exec" => Command::Exec,
        "undo" => Command::Undo,
        "plan" => {
            return sub(
                "plan",
                &[
                    ("show", Command::PlanShow),
                    ("from-targets", Command::PlanFromTargets),
                ],
            );
        }
        "journal" => {
            return sub(
                "journal",
                &[
                    ("recover", Command::JournalRecover),
                    ("resume", Command::JournalResume),
                    ("rollback", Command::JournalRollback),
                    ("show", Command::JournalShow),
                    ("fault-points", Command::JournalFaultPoints),
                    ("retry-held", Command::JournalRetryHeld),
                ],
            );
        }
        "quarantine" => {
            return sub(
                "quarantine",
                &[
                    ("expiring", Command::QuarantineExpiring),
                    ("purge", Command::QuarantinePurge),
                ],
            );
        }
        "baseline" => {
            return sub(
                "baseline",
                &[
                    ("build", Command::BaselineBuild),
                    ("info", Command::BaselineInfo),
                ],
            );
        }
        "kb" => return sub("kb", &[("lint", Command::KbLint)]),
        other => return Err(format!("unknown verb '{other}'")),
    };
    Ok(Verb::Run(cmd, rest(1)))
}

/// The options and positional arguments of one verb.
#[derive(Debug, Default)]
struct Parsed {
    positional: Vec<String>,
    values: Vec<(&'static str, String)>,
    flags: Vec<&'static str>,
}

impl Parsed {
    fn value(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }

    fn flag(&self, name: &str) -> bool {
        self.flags.contains(&name)
    }

    fn path(&self, name: &str) -> Option<PathBuf> {
        self.value(name).map(PathBuf::from)
    }
}

/// Splits `args` of verb `verb` by the option table: `with_value` and `flags` are long names without
/// `--`. `-o` stands for `--out`.
fn options(
    verb: &str,
    args: &[String],
    with_value: &[&'static str],
    flags: &[&'static str],
) -> Result<Parsed, String> {
    let mut out = Parsed::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let Some(long) = arg
            .strip_prefix("--")
            .or_else(|| (arg == "-o").then_some("out"))
        else {
            if arg.starts_with('-') && arg.len() > 1 {
                return Err(format!("{verb}: unknown option '{arg}'"));
            }
            out.positional.push(arg.clone());
            continue;
        };
        let (name, inline) = match long.split_once('=') {
            Some((n, v)) => (n, Some(v.to_owned())),
            None => (long, None),
        };
        if let Some(&name) = with_value.iter().find(|n| **n == name) {
            if out.value(name).is_some() {
                return Err(format!("{verb}: --{name} given twice"));
            }
            let value = match inline {
                Some(v) => v,
                None => it
                    .next()
                    .cloned()
                    .ok_or_else(|| format!("{verb}: --{name} needs a value"))?,
            };
            if value.is_empty() {
                return Err(format!("{verb}: --{name} needs a non-empty value"));
            }
            out.values.push((name, value));
        } else if let Some(&name) = flags.iter().find(|n| **n == name) {
            if inline.is_some() {
                return Err(format!("{verb}: --{name} takes no value"));
            }
            if out.flag(name) {
                return Err(format!("{verb}: --{name} given twice"));
            }
            out.flags.push(name);
        } else {
            return Err(format!("{verb}: unknown option '{arg}'"));
        }
    }
    Ok(out)
}

/// Exactly one positional argument.
fn one_positional(verb: &str, what: &str, p: &Parsed) -> Result<String, String> {
    match p.positional.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(format!("{verb}: missing {what}")),
        [_, extra, ..] => Err(format!("{verb}: unexpected argument '{extra}'")),
    }
}

fn no_positional(verb: &str, p: &Parsed) -> Result<(), String> {
    match p.positional.first() {
        None => Ok(()),
        Some(extra) => Err(format!("{verb}: unexpected argument '{extra}'")),
    }
}

fn inventory(args: &[String]) -> Result<InventoryArgs, String> {
    let p = options("inventory", args, &["out"], &["json"])?;
    no_positional("inventory", &p)?;
    Ok(InventoryArgs {
        json: p.flag("json"),
        out: p.path("out"),
    })
}

fn harvest(args: &[String]) -> Result<HarvestArgs, String> {
    let p = options("harvest", args, &["out"], &[])?;
    Ok(HarvestArgs {
        program_id: one_positional("harvest", "<program_id>", &p)?,
        out: p.path("out"),
    })
}

fn uninstall(args: &[String]) -> Result<UninstallArgs, String> {
    let p = options("uninstall", args, &["out", "fp"], &["quiet"])?;
    let program_id = one_positional("uninstall", "<program_id>", &p)?;
    if !p.flag("quiet") {
        return Err(
            "uninstall: only the quiet uninstall is implemented; pass --quiet (the interactive \
             uninstall comes with the UI broker)"
                .into(),
        );
    }
    Ok(UninstallArgs {
        program_id,
        fp: p.path("fp"),
        out: p.path("out"),
    })
}

fn scan(args: &[String]) -> Result<ScanArgs, String> {
    let p = options("scan", args, &["out", "fp", "mode", "path", "app"], &[])?;
    no_positional("scan", &p)?;
    let from = match (p.path("fp"), p.value("path")) {
        (Some(fp), None) => {
            let mode = match p.value("mode").unwrap_or("post") {
                "post" => ScanMode::Post,
                "external" => ScanMode::External,
                "forced" => ScanMode::Forced,
                other => {
                    return Err(format!(
                        "scan: unknown mode '{other}' (post, external or forced)"
                    ));
                }
            };
            ScanFrom::Fingerprint { fp, mode }
        }
        (None, Some(path)) => {
            if p.value("mode").is_some() {
                return Err("scan: --path always scans in forced mode; drop --mode".into());
            }
            ScanFrom::Path(path.to_owned())
        }
        (Some(_), Some(_)) => return Err("scan: give either --fp or --path, not both".into()),
        (None, None) => return Err("scan: needs --fp <fp.json> or --path <dir>".into()),
    };
    let out = p
        .path("out")
        .ok_or("scan: needs -o <plan.json> (the sidecar goes next to it)")?;
    Ok(ScanArgs {
        from,
        app: p.value("app").map(str::to_owned),
        out,
    })
}

fn plan_show(args: &[String]) -> Result<PlanShowArgs, String> {
    let p = options("plan show", args, &[], &[])?;
    Ok(PlanShowArgs {
        plan: PathBuf::from(one_positional("plan show", "<plan.json>", &p)?),
    })
}

fn baseline_build(args: &[String]) -> Result<BaselineBuildArgs, String> {
    let p = options("baseline build", args, &["out"], &[])?;
    no_positional("baseline build", &p)?;
    Ok(BaselineBuildArgs {
        out: p.path("out").ok_or("baseline build: needs --out <file>")?,
    })
}

fn baseline_info(args: &[String]) -> Result<BaselineInfoArgs, String> {
    let p = options("baseline info", args, &[], &[])?;
    Ok(BaselineInfoArgs {
        file: PathBuf::from(one_positional("baseline info", "<file>", &p)?),
    })
}

fn walk_floor(args: &[String]) -> Result<WalkFloorArgs, String> {
    let verb = "walk-floor";
    let p = options(verb, args, &["runs", "out"], &[])?;
    no_positional(verb, &p)?;
    let runs = match p.value("runs") {
        None => WALK_FLOOR_RUNS,
        Some(text) => match text.parse::<u32>() {
            Ok(n) if (1..=WALK_FLOOR_MAX_RUNS).contains(&n) => n,
            _ => {
                return Err(format!(
                    "walk-floor: --runs takes a number from 1 to {WALK_FLOOR_MAX_RUNS}, not '{text}'"
                ));
            }
        },
    };
    Ok(WalkFloorArgs {
        runs,
        out: p.path("out"),
    })
}

fn no_arguments(verb: &str, args: &[String]) -> Result<(), String> {
    let p = options(verb, args, &[], &[])?;
    no_positional(verb, &p)
}

fn optional_session(verb: &str, args: &[String]) -> Result<Option<String>, String> {
    let p = options(verb, args, &["session"], &[])?;
    no_positional(verb, &p)?;
    Ok(p.value("session").map(str::to_owned))
}

fn from_targets(args: &[String]) -> Result<FromTargetsArgs, String> {
    let verb = "plan from-targets";
    let p = options(verb, args, &["out"], &[])?;
    let targets = PathBuf::from(one_positional(verb, "<targets.json>", &p)?);
    let out = p
        .path("out")
        .ok_or("plan from-targets: needs -o <plan.json> (the sidecar goes next to it)")?;
    Ok(FromTargetsArgs { targets, out })
}

fn exec(args: &[String]) -> Result<ExecArgs, String> {
    let p = options(
        "exec",
        args,
        &["plan", "confirm", "select", "restore-point", "fp", "out"],
        &["allow-irreversible"],
    )?;
    no_positional("exec", &p)?;
    let plan = p.path("plan").ok_or("exec: needs --plan <plan.json>")?;
    let confirm = p
        .value("confirm")
        .ok_or("exec: needs --confirm <hash> (the confirm hash of the plan and the selection)")?
        .to_owned();
    let restore_point = match p.value("restore-point") {
        None => RestorePointArg::default(),
        Some("off") => RestorePointArg::Off,
        Some("high-risk") => RestorePointArg::HighRisk,
        Some("always") => RestorePointArg::Always,
        Some(other) => {
            return Err(format!(
                "exec: unknown --restore-point '{other}' (off, high-risk or always)"
            ));
        }
    };
    Ok(ExecArgs {
        plan,
        confirm,
        select: p.path("select"),
        allow_irreversible: p.flag("allow-irreversible"),
        restore_point,
        fp: p.path("fp"),
        out: p.path("out"),
    })
}

fn undo(args: &[String]) -> Result<UndoArgs, String> {
    let p = options("undo", args, &["session", "items", "confirm", "out"], &[])?;
    no_positional("undo", &p)?;
    Ok(UndoArgs {
        session: p
            .value("session")
            .ok_or("undo: needs --session <id>")?
            .to_owned(),
        items: p.path("items"),
        confirm: p.value("confirm").map(str::to_owned),
        out: p.path("out"),
    })
}

/// `--ids a b c` and `--confirm-user-data a b`: each takes every following argument up to the next one
/// that starts with `-`. The rest goes through [`options`].
fn quarantine_purge(args: &[String]) -> Result<PurgeArgs, String> {
    let verb = "quarantine purge";
    let mut ids: Vec<String> = Vec::new();
    let mut user_data: Vec<String> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    let mut rest: Vec<String> = Vec::new();
    let mut it = args.iter().peekable();
    while let Some(arg) = it.next() {
        let list = match arg.as_str() {
            "--ids" => &mut ids,
            "--confirm-user-data" => &mut user_data,
            _ => {
                rest.push(arg.clone());
                continue;
            }
        };
        if seen.contains(&arg.as_str()) {
            return Err(format!("{verb}: {arg} given twice"));
        }
        seen.push(arg.as_str());
        let before = list.len();
        while let Some(value) = it.next_if(|v| !(v.starts_with('-') && v.len() > 1)) {
            if !value.is_empty() {
                list.push(value.clone());
            }
        }
        if list.len() == before {
            return Err(format!("{verb}: {arg} needs at least one <session/op> id"));
        }
    }
    let p = options(verb, &rest, &[], &["yes-irreversible"])?;
    no_positional(verb, &p)?;
    if ids.is_empty() {
        return Err(format!("{verb}: needs --ids <session/op>..."));
    }
    if !p.flag("yes-irreversible") {
        return Err(format!(
            "{verb}: deleting quarantined items cannot be undone; pass --yes-irreversible"
        ));
    }
    if let Some(stray) = user_data.iter().find(|u| !ids.contains(u)) {
        return Err(format!(
            "{verb}: --confirm-user-data names {stray}, which --ids does not list"
        ));
    }
    Ok(PurgeArgs {
        ids,
        confirm_user_data: user_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(line: &str) -> Result<Invocation, String> {
        let args: Vec<String> = line.split_whitespace().map(String::from).collect();
        parse(&args)
    }

    fn err(line: &str) -> String {
        p(line).expect_err(line)
    }

    #[test]
    fn later_milestone_verbs_are_recognised_and_keep_their_arguments() {
        let cases = [(
            "kb lint a.json b.json --baselines vm/baselines/",
            Command::KbLint,
        )];
        for (line, want) in cases {
            match p(line) {
                Ok(Invocation::NotImplemented(cmd, _)) => {
                    assert_eq!(cmd, want, "{line}");
                    assert_ne!(cmd.milestone(), "M1a", "{line}");
                }
                other => panic!("{line}: {other:?}"),
            }
        }
        assert_eq!(p("--stdio"), Ok(Invocation::Stdio));
        assert_eq!(
            p("--stdio extra"),
            Err("--stdio: unexpected argument 'extra'".into())
        );
        assert_eq!(
            p("kb lint a.json"),
            Ok(Invocation::NotImplemented(
                Command::KbLint,
                vec!["a.json".into()]
            ))
        );
    }

    #[test]
    fn baseline_verbs() {
        assert_eq!(
            p("baseline build --out x.tsv.gz"),
            Ok(Invocation::BaselineBuild(BaselineBuildArgs {
                out: PathBuf::from("x.tsv.gz")
            }))
        );
        assert_eq!(
            p("baseline build -o x"),
            Ok(Invocation::BaselineBuild(BaselineBuildArgs {
                out: PathBuf::from("x")
            }))
        );
        assert_eq!(
            p("baseline info x.tsv.gz"),
            Ok(Invocation::BaselineInfo(BaselineInfoArgs {
                file: PathBuf::from("x.tsv.gz")
            }))
        );
        assert_eq!(p("hello"), Ok(Invocation::Hello));
        assert_eq!(
            p("walk-floor"),
            Ok(Invocation::WalkFloor(WalkFloorArgs {
                runs: WALK_FLOOR_RUNS,
                out: None
            }))
        );
        assert_eq!(
            p("walk-floor --runs 5 -o floor.json"),
            Ok(Invocation::WalkFloor(WalkFloorArgs {
                runs: 5,
                out: Some(PathBuf::from("floor.json"))
            }))
        );
        for bad in [
            "walk-floor --runs 0",
            "walk-floor --runs 21",
            "walk-floor --runs x",
        ] {
            assert!(err(bad).contains("--runs takes a number"), "{bad}");
        }
        assert!(err("walk-floor now").contains("unexpected argument"));
        assert!(err("hello now").contains("unexpected argument"));
        assert!(err("baseline build").contains("needs --out"));
        assert!(err("baseline build --out a b").contains("unexpected argument"));
        assert!(err("baseline info").contains("missing <file>"));
        assert!(err("baseline info a b").contains("unexpected argument"));
        assert!(err("baseline").contains("needs a sub-verb"));
        assert!(err("baseline load").contains("unknown 'baseline' sub-verb"));
    }

    fn exec_verb(line: &str) -> ExecVerb {
        match p(line) {
            Ok(Invocation::Executor(verb)) => verb,
            other => panic!("{line}: {other:?}"),
        }
    }

    #[test]
    fn executor_verbs_and_their_arguments() {
        assert_eq!(
            exec_verb("plan from-targets t.json -o plan.json"),
            ExecVerb::PlanFromTargets(FromTargetsArgs {
                targets: "t.json".into(),
                out: "plan.json".into()
            })
        );
        assert_eq!(
            exec_verb(
                "exec --plan p.json --confirm abc --select s.json --allow-irreversible \
                 --restore-point always --fp fp.json -o r.json"
            ),
            ExecVerb::Exec(ExecArgs {
                plan: "p.json".into(),
                confirm: "abc".into(),
                select: Some("s.json".into()),
                allow_irreversible: true,
                restore_point: RestorePointArg::Always,
                fp: Some("fp.json".into()),
                out: Some("r.json".into())
            })
        );
        assert_eq!(
            exec_verb("exec --plan p.json --confirm abc"),
            ExecVerb::Exec(ExecArgs {
                plan: "p.json".into(),
                confirm: "abc".into(),
                select: None,
                allow_irreversible: false,
                restore_point: RestorePointArg::HighRisk,
                fp: None,
                out: None
            })
        );
        for (word, want) in [
            ("off", RestorePointArg::Off),
            ("high-risk", RestorePointArg::HighRisk),
            ("always", RestorePointArg::Always),
        ] {
            match exec_verb(&format!("exec --plan p --confirm c --restore-point {word}")) {
                ExecVerb::Exec(a) => assert_eq!(a.restore_point, want),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(
            exec_verb("undo --session s1 --items i.json --confirm h -o u.json"),
            ExecVerb::Undo(UndoArgs {
                session: "s1".into(),
                items: Some("i.json".into()),
                confirm: Some("h".into()),
                out: Some("u.json".into())
            })
        );
        assert_eq!(
            exec_verb("undo --session s1"),
            ExecVerb::Undo(UndoArgs {
                session: "s1".into(),
                items: None,
                confirm: None,
                out: None
            })
        );
        assert_eq!(exec_verb("journal recover"), ExecVerb::JournalRecover);
        assert_eq!(exec_verb("journal resume"), ExecVerb::JournalResume(None));
        assert_eq!(
            exec_verb("journal resume --session s1"),
            ExecVerb::JournalResume(Some("s1".into()))
        );
        assert_eq!(
            exec_verb("journal rollback --session=s1"),
            ExecVerb::JournalRollback(Some("s1".into()))
        );
        assert_eq!(
            exec_verb("journal rollback"),
            ExecVerb::JournalRollback(None)
        );
        assert_eq!(
            exec_verb("journal show --session s1"),
            ExecVerb::JournalShow("s1".into())
        );
        assert_eq!(
            exec_verb("journal fault-points"),
            ExecVerb::JournalFaultPoints
        );
        assert_eq!(
            exec_verb("journal retry-held --session s1"),
            ExecVerb::JournalRetryHeld("s1".into())
        );
        assert_eq!(
            exec_verb("quarantine expiring"),
            ExecVerb::QuarantineExpiring
        );
        assert_eq!(
            exec_verb("quarantine purge --ids s/1 s/2 --yes-irreversible --confirm-user-data s/2"),
            ExecVerb::QuarantinePurge(PurgeArgs {
                ids: vec!["s/1".into(), "s/2".into()],
                confirm_user_data: vec!["s/2".into()]
            })
        );
        assert_eq!(
            exec_verb("quarantine purge --yes-irreversible --ids s/3"),
            ExecVerb::QuarantinePurge(PurgeArgs {
                ids: vec!["s/3".into()],
                confirm_user_data: Vec::new()
            })
        );
        for verb in [
            exec_verb("exec --plan p --confirm c"),
            exec_verb("journal fault-points"),
            exec_verb("plan from-targets t -o p"),
        ] {
            assert_eq!(verb.command().milestone(), "M2");
        }
        assert!(Command::PlanFromTargets.is_rig_tool());
        assert!(Command::JournalFaultPoints.is_rig_tool());
        assert!(!Command::Exec.is_rig_tool());
    }

    #[test]
    fn executor_usage_errors() {
        assert!(err("plan from-targets -o p.json").contains("missing <targets.json>"));
        assert!(err("plan from-targets t.json").contains("-o <plan.json>"));
        assert!(err("exec --confirm c").contains("--plan"));
        assert!(err("exec --plan p").contains("--confirm"));
        assert!(err("exec --plan p --confirm c --restore-point never").contains("--restore-point"));
        assert!(err("exec --plan p --confirm c --data-root d").contains("unknown option"));
        assert!(err("exec --plan p --confirm c extra").contains("unexpected argument"));
        assert!(err("undo").contains("--session"));
        assert!(err("undo --session s --data-root d").contains("unknown option"));
        assert!(err("journal recover --session s").contains("unknown option"));
        assert!(err("journal show").contains("--session"));
        assert!(err("journal retry-held").contains("--session"));
        assert!(err("journal retry-held --session s --all").contains("unknown option"));
        assert!(err("journal fault-points x").contains("unexpected argument"));
        assert!(err("journal delete").contains("unknown 'journal' sub-verb"));
        assert!(err("quarantine").contains("needs a sub-verb"));
        assert!(err("quarantine list").contains("unknown 'quarantine' sub-verb"));
        assert!(err("quarantine expiring --all").contains("unknown option"));
        assert!(err("quarantine purge --ids s/1").contains("--yes-irreversible"));
        assert!(err("quarantine purge --yes-irreversible").contains("--ids"));
        assert!(err("quarantine purge --ids --yes-irreversible").contains("at least one"));
        assert!(err("quarantine purge --ids a --ids b --yes-irreversible").contains("given twice"));
        assert!(
            err("quarantine purge --ids s/1 --yes-irreversible --confirm-user-data s/2")
                .contains("does not list")
        );
        assert!(
            err("quarantine purge --ids s/1 --yes-irreversible --yes-irreversible")
                .contains("given twice")
        );
    }

    #[test]
    fn version_help_and_verb_errors() {
        assert_eq!(p("--version"), Ok(Invocation::Version));
        assert_eq!(p("-V"), Ok(Invocation::Version));
        assert_eq!(p("--help"), Ok(Invocation::Help));
        assert_eq!(p("help"), Ok(Invocation::Help));
        assert!(err("").contains("missing verb"));
        assert!(err("frobnicate").contains("unknown verb"));
        assert!(err("plan").contains("needs a sub-verb"));
        assert!(err("journal delete").contains("unknown 'journal' sub-verb"));
    }

    #[test]
    fn inventory_arguments() {
        assert_eq!(
            p("inventory --json"),
            Ok(Invocation::Inventory(InventoryArgs {
                json: true,
                out: None
            }))
        );
        assert_eq!(
            p("inventory -o inv.json"),
            Ok(Invocation::Inventory(InventoryArgs {
                json: false,
                out: Some("inv.json".into())
            }))
        );
        assert_eq!(
            p("inventory"),
            Ok(Invocation::Inventory(InventoryArgs::default()))
        );
        assert!(err("inventory --json --json").contains("given twice"));
        assert!(err("inventory --json=yes").contains("takes no value"));
        assert!(err("inventory extra").contains("unexpected argument"));
        assert!(err("inventory --all").contains("unknown option"));
    }

    #[test]
    fn harvest_arguments() {
        assert_eq!(
            p("harvest HKLM|64|Git_is1 -o fp.json"),
            Ok(Invocation::Harvest(HarvestArgs {
                program_id: "HKLM|64|Git_is1".into(),
                out: Some("fp.json".into())
            }))
        );
        assert_eq!(
            p("harvest --out=fp.json Git_is1"),
            Ok(Invocation::Harvest(HarvestArgs {
                program_id: "Git_is1".into(),
                out: Some("fp.json".into())
            }))
        );
        assert!(err("harvest -o fp.json").contains("missing <program_id>"));
        assert!(err("harvest a b").contains("unexpected argument 'b'"));
        assert!(err("harvest a -o").contains("needs a value"));
        assert!(err("harvest a -o x -o y").contains("given twice"));
        assert!(err("harvest a -x").contains("unknown option"));
    }

    #[test]
    fn uninstall_arguments() {
        assert_eq!(
            p("uninstall app --quiet --fp fp.json -o run.json"),
            Ok(Invocation::Uninstall(UninstallArgs {
                program_id: "app".into(),
                fp: Some("fp.json".into()),
                out: Some("run.json".into())
            }))
        );
        assert_eq!(
            p("uninstall app --quiet"),
            Ok(Invocation::Uninstall(UninstallArgs {
                program_id: "app".into(),
                fp: None,
                out: None
            }))
        );
        assert!(err("uninstall app -o run.json").contains("--quiet"));
        assert!(err("uninstall --quiet").contains("missing <program_id>"));
        assert!(err("uninstall app --quiet --fp").contains("needs a value"));
    }

    #[test]
    fn scan_arguments() {
        assert_eq!(
            p("scan --fp fp.json --mode post --app firefox -o plan.json"),
            Ok(Invocation::Scan(ScanArgs {
                from: ScanFrom::Fingerprint {
                    fp: "fp.json".into(),
                    mode: ScanMode::Post
                },
                app: Some("firefox".into()),
                out: "plan.json".into()
            }))
        );
        for (mode, want) in [
            ("external", ScanMode::External),
            ("forced", ScanMode::Forced),
        ] {
            match p(&format!("scan --fp f --mode {mode} -o p")) {
                Ok(Invocation::Scan(ScanArgs {
                    from: ScanFrom::Fingerprint { mode, .. },
                    ..
                })) => assert_eq!(mode, want),
                other => panic!("{other:?}"),
            }
        }
        // The default mode is post.
        match p("scan --fp f -o p") {
            Ok(Invocation::Scan(ScanArgs {
                from: ScanFrom::Fingerprint { mode, .. },
                app: None,
                ..
            })) => assert_eq!(mode, ScanMode::Post),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            p(r"scan --path C:\Tools\procexp -o plan.json"),
            Ok(Invocation::Scan(ScanArgs {
                from: ScanFrom::Path(r"C:\Tools\procexp".into()),
                app: None,
                out: "plan.json".into()
            }))
        );
        assert!(err("scan --fp f --mode later -o p").contains("unknown mode"));
        assert!(err("scan --fp f --path d -o p").contains("not both"));
        assert!(err("scan -o p").contains("--fp"));
        assert!(err("scan --fp f").contains("-o <plan.json>"));
        assert!(err("scan --path d --mode post -o p").contains("forced"));
        assert!(err("scan --fp f -o p extra").contains("unexpected argument"));
    }

    #[test]
    fn plan_show_arguments() {
        assert_eq!(
            p("plan show x.json"),
            Ok(Invocation::PlanShow(PlanShowArgs {
                plan: "x.json".into()
            }))
        );
        assert!(err("plan show").contains("missing <plan.json>"));
        assert!(err("plan show a b").contains("unexpected argument"));
    }

    #[test]
    fn a_lone_dash_is_a_positional_argument() {
        assert_eq!(
            p("harvest -"),
            Ok(Invocation::Harvest(HarvestArgs {
                program_id: "-".into(),
                out: None
            }))
        );
    }
}
