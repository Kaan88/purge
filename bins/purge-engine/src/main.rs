//! `purge-engine`: one executable, three roles (ENGINE_PLAN.md §3.1, §3.4).
//!
//! - `--stdio`: medium-integrity server for the UI (inventory, icons, sizes, per-user work);
//! - `--broker`: the elevated broker (harvest, uninstall, scan, plan, consent, execute, undo);
//! - CLI verbs for the VM rig and power users. Headless `exec` exists only with the `rig-exec` feature.
//!
//! Milestone: CLI verbs in M1a, `exec`/`undo`/`journal` in M2, `--stdio` and `--broker` in M3 (§11.1).
//! In M0 every verb is recognised and reports that it is not implemented yet.

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("purge-engine supports x86_64 Windows only (ENGINE_PLAN.md §3.2)");

use std::process::ExitCode;

const USAGE: &str = "\
usage: purge-engine <verb> [args]

modes:
  --stdio                                   serve the UI over stdin/stdout (medium integrity)
  --broker --pipe <name> --parent <pid> --parent-ctime <filetime>
                                            elevated broker for the UI

verbs:
  inventory --json
  harvest <program_id> -o <fp.json>
  uninstall <program_id> --quiet [--fp <fp.json>] -o <run.json>
  scan (--fp <fp.json> [--mode post|external|forced] | --path <dir>) -o <plan.json>
  plan show <plan.json>
  exec --plan <plan.json> --confirm <hash>
  undo --session <id> [--confirm <hash>]
  journal recover|resume|rollback
  kb lint <pack.json>... [--baselines <dir>]

  --version, -V                             print the version
  --help, -h                                print this help
";

/// A recognised top-level command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    Stdio,
    Broker,
    Inventory,
    Harvest,
    Uninstall,
    Scan,
    PlanShow,
    Exec,
    Undo,
    JournalRecover,
    JournalResume,
    JournalRollback,
    KbLint,
}

impl Command {
    fn name(self) -> &'static str {
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
}

/// The result of parsing the command line.
#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    Version,
    Help,
    /// A command plus its remaining arguments (not interpreted in M0).
    Run(Command, Vec<String>),
}

/// Recognises the verb (and sub-verb) of a command line. Arguments after the verb are kept as-is.
fn parse(args: &[String]) -> Result<Invocation, String> {
    let Some(first) = args.first() else {
        return Err("missing verb".into());
    };
    let rest = |n: usize| args[n..].to_vec();
    let sub = |verb: &str, choices: &[(&str, Command)]| -> Result<Invocation, String> {
        let Some(s) = args.get(1) else {
            return Err(format!("'{verb}' needs a sub-verb"));
        };
        choices
            .iter()
            .find(|(name, _)| name == s)
            .map(|&(_, cmd)| Invocation::Run(cmd, rest(2)))
            .ok_or_else(|| format!("unknown '{verb}' sub-verb '{s}'"))
    };
    let cmd = match first.as_str() {
        "--version" | "-V" => return Ok(Invocation::Version),
        "--help" | "-h" | "help" => return Ok(Invocation::Help),
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
    Ok(Invocation::Run(cmd, rest(1)))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(&args) {
        Ok(Invocation::Version) => {
            println!("purge-engine {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Invocation::Help) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Invocation::Run(cmd, _args)) => {
            println!("purge-engine {}: not implemented in M0", cmd.name());
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("purge-engine: {e}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(line: &str) -> Result<Invocation, String> {
        let args: Vec<String> = line.split_whitespace().map(String::from).collect();
        parse(&args)
    }

    #[test]
    fn recognises_every_verb_of_the_cli_contract() {
        let cases = [
            ("--stdio", Command::Stdio),
            (
                "--broker --pipe p --parent 1 --parent-ctime 2",
                Command::Broker,
            ),
            ("inventory --json", Command::Inventory),
            ("harvest app -o fp.json", Command::Harvest),
            (
                "uninstall app --quiet --fp fp.json -o run.json",
                Command::Uninstall,
            ),
            ("scan --fp fp.json --mode post -o plan.json", Command::Scan),
            ("plan show plan.json", Command::PlanShow),
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
                Ok(Invocation::Run(cmd, _)) => assert_eq!(cmd, want, "{line}"),
                other => panic!("{line}: {other:?}"),
            }
        }
    }

    #[test]
    fn keeps_arguments_after_the_verb() {
        assert_eq!(
            p("plan show x.json"),
            Ok(Invocation::Run(Command::PlanShow, vec!["x.json".into()]))
        );
    }

    #[test]
    fn version_help_and_errors() {
        assert_eq!(p("--version"), Ok(Invocation::Version));
        assert_eq!(p("-V"), Ok(Invocation::Version));
        assert_eq!(p("--help"), Ok(Invocation::Help));
        assert!(p("").is_err());
        assert!(p("frobnicate").is_err());
        assert!(p("plan").is_err());
        assert!(p("journal delete").is_err());
    }
}
