//! Command-line parsing: the verb (and sub-verb), then the arguments of each implemented verb
//! (ENGINE_PLAN.md §3.4).
//!
//! Options are `--name value` or `--name=value`; `-o` is the short form of `--out`. An option given twice,
//! an unknown option, a missing value and a missing or extra positional argument are usage errors (exit
//! code 2). Verbs of later milestones are recognised, their arguments are not interpreted, and they report
//! "not implemented" (exit code 1).

use std::path::PathBuf;

use purge_model::ScanMode;

/// The usage text printed by `--help` and after a usage error.
pub const USAGE: &str = "\
usage: purge-engine <verb> [args]

modes:
  --stdio                                   serve the UI over stdin/stdout (medium integrity)
  --broker --pipe <name> --parent <pid> --parent-ctime <filetime>
                                            elevated broker for the UI

verbs:
  inventory [--json] [-o <inv.json>]
  harvest <program_id> [-o <fp.json>]
  uninstall <program_id> --quiet [--fp <fp.json>] [-o <run.json>]
  scan --fp <fp.json> [--mode post|external|forced] [--app <id>] -o <plan.json>
  scan --path <dir> [--app <id>] -o <plan.json>
  plan show <plan.json>
  exec --plan <plan.json> --confirm <hash>
  undo --session <id> [--confirm <hash>]
  journal recover|resume|rollback
  kb lint <pack.json>... [--baselines <dir>]

  <program_id> is an inventory id (HKLM|64|Git_is1) or the Uninstall key name of exactly one entry.
  scan also writes the sidecar <plan>.scan.json next to the plan.

exit codes: 0 ok, 1 not implemented, 2 usage or precondition, 3 runtime error,
            4 uninstall failed, cancelled or timed out

  --version, -V                             print the version
  --help, -h                                print this help
";

/// A recognised top-level command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `--stdio`.
    Stdio,
    /// `--broker`.
    Broker,
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
    /// `kb lint`.
    KbLint,
}

impl Command {
    /// The command as typed.
    pub fn name(self) -> &'static str {
        match self {
            Command::Stdio => "--stdio",
            Command::Broker => "--broker",
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
            | Command::JournalRollback => "M2",
            Command::KbLint => "M4",
            Command::Stdio | Command::Broker => "M3",
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
        Command::Inventory => inventory(&rest).map(Invocation::Inventory),
        Command::Harvest => harvest(&rest).map(Invocation::Harvest),
        Command::Uninstall => uninstall(&rest).map(Invocation::Uninstall),
        Command::Scan => scan(&rest).map(Invocation::Scan),
        Command::PlanShow => plan_show(&rest).map(Invocation::PlanShow),
        other => Ok(Invocation::NotImplemented(other, rest)),
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
        "--broker" => Command::Broker,
        "inventory" => Command::Inventory,
        "harvest" => Command::Harvest,
        "uninstall" => Command::Uninstall,
        "scan" => Command::Scan,
        "exec" => Command::Exec,
        "undo" => Command::Undo,
        "plan" => return sub("plan", &[("show", Command::PlanShow)]),
        "journal" => {
            return sub(
                "journal",
                &[
                    ("recover", Command::JournalRecover),
                    ("resume", Command::JournalResume),
                    ("rollback", Command::JournalRollback),
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
        let cases = [
            (
                "--broker --pipe p --parent 1 --parent-ctime 2",
                Command::Broker,
            ),
            ("--stdio", Command::Stdio),
            ("exec --plan plan.json --confirm abc", Command::Exec),
            ("undo --session s1", Command::Undo),
            ("journal recover", Command::JournalRecover),
            ("journal resume", Command::JournalResume),
            ("journal rollback", Command::JournalRollback),
            (
                "kb lint a.json b.json --baselines vm/baselines/",
                Command::KbLint,
            ),
        ];
        for (line, want) in cases {
            match p(line) {
                Ok(Invocation::NotImplemented(cmd, _)) => {
                    assert_eq!(cmd, want, "{line}");
                    assert_ne!(cmd.milestone(), "M1a", "{line}");
                }
                other => panic!("{line}: {other:?}"),
            }
        }
        assert_eq!(
            p("undo --session s1"),
            Ok(Invocation::NotImplemented(
                Command::Undo,
                vec!["--session".into(), "s1".into()]
            ))
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
