//! `uninstall.route` and `uninstall.run_user` (M3 design 3.2, 3.5; package M3-RUNNER).
//!
//! The medium engine runs the uninstaller of a per-user entry, or of a machine-scope entry whose
//! uninstaller path a user can write. [`handle_route`] answers where a program's uninstaller belongs
//! and what it will be; [`handle_run_user`] runs it at the engine's own (medium) level, inside a Job
//! object through the [`ProcessHost`], and sends one `uninstall.progress` notification per pipeline
//! step.
//!
//! The dispatcher in `stdio.rs` owns the inventory and the transport, so the two handlers are
//! self-contained functions over the request, the pipeline sources, the process host, the token facts
//! and a [`Notify`] sink (the same shape as [`crate::icons`]).
//!
//! Three rules (M3_DESIGN.md, package M3-RUNNER):
//!
//! 1. A broker-route program is refused with `wrong_route`: the medium engine never runs a command
//!    whose path is writable by administrators alone.
//! 2. A run is refused unless the engine's token has the user and the elevation of the shell owner's
//!    token ("start Purge normally"). With UAC off both are elevated, so a run is allowed.
//! 3. The command shown is the command run: [`crate::pipeline::uninstall_commands`] produces the
//!    exact command lines, [`handle_route`] answers with them and [`handle_run_user`] passes the
//!    matching command to [`crate::pipeline::uninstall_with_command`].
//!
//! No token is changed and no privilege is enabled: the engine already runs with the user's token, and
//! the job and its creation belong to `purge-inventory`'s [`ProcessHost`].

use std::path::Path;

use purge_inventory::runner::{ProcessHost, RunOptions};
use purge_model::{InventoryEntry, ProgramId};
use purge_rpc::error::{ErrorData, ErrorObject, IdKind};
use purge_rpc::frame::{FrameError, RequestId};
use purge_rpc::methods::{
    ProgramParams, Progress, Route, RouteInfo, RunUserParams, RunUserResult, RunningProcess,
    ServerNotification,
};
use purge_rpc::table::Notify;
use purge_source::types::ProcessInfo;
use purge_win::os::Win32Error;
use purge_win::token::{self, TokenFacts};

use crate::pipeline::{self, PipelineError, Sources};

// ---------------------------------------------------------------------------------------------------------
// Token facts and the level rule
// ---------------------------------------------------------------------------------------------------------

/// The two tokens the level rule compares: the engine's and the shell owner's (M3 design 3.5).
///
/// The engine runs a medium-route uninstaller only when its token has the same user **and** the same
/// elevation as the token of the process that owns the shell window (`GetShellWindow`). A missing
/// shell window is a refusal too: without it the engine cannot show that it is not above the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Level {
    /// The engine process's token facts.
    pub engine: TokenFacts,
    /// The shell owner's token facts; `None` when there is no shell window.
    pub shell: Option<TokenFacts>,
}

impl Level {
    /// The level of this process against the live shell ([`token::current_process_facts`],
    /// [`token::shell_owner_facts`]).
    pub fn live() -> Result<Level, Win32Error> {
        Ok(Level {
            engine: token::current_process_facts()?,
            shell: token::shell_owner_facts()?,
        })
    }

    /// Whether the engine may run a medium-route uninstaller.
    pub fn same_user_and_elevation(&self) -> bool {
        self.shell
            .as_ref()
            .is_some_and(|shell| self.engine.same_user_and_elevation(shell))
    }

    /// The refusal of rule 2, or `Ok(())`. The error is a `runtime` error whose message says what
    /// differs and asks for a normal start ("start Purge normally").
    pub fn check(&self) -> Result<(), ErrorObject> {
        match &self.shell {
            None => Err(ErrorObject::runtime(
                "start Purge normally: the shell window could not be found, so Purge cannot show \
                 that it runs at the user's level",
            )),
            Some(shell) if self.engine.same_user_and_elevation(shell) => Ok(()),
            Some(shell) => Err(ErrorObject::runtime(format!(
                "start Purge normally: the engine runs as {} ({}) but the shell as {} ({}); Purge \
                 runs a medium-route uninstaller only at the user's level",
                self.engine.user_sid,
                if self.engine.elevated {
                    "elevated"
                } else {
                    "medium"
                },
                shell.user_sid,
                if shell.elevated { "elevated" } else { "medium" },
            ))),
        }
    }
}

// ---------------------------------------------------------------------------------------------------------
// uninstall.route
// ---------------------------------------------------------------------------------------------------------

/// Answers `uninstall.route`: where `program_id`'s uninstaller belongs and the commands it names.
///
/// A broker-route answer is not a refusal here: the client shows it and asks the broker to prepare the
/// program instead. Only [`handle_run_user`] refuses it.
pub fn handle_route(
    params: &ProgramParams,
    sources: Sources<'_>,
) -> Result<RouteInfo, ErrorObject> {
    let inventory = pipeline::inventory(sources);
    let entry = inventory
        .doc
        .entry(&params.program_id)
        .ok_or_else(|| gone_program(&params.program_id))?;
    route_info(entry, sources)
}

/// The `RouteInfo` of one entry, from the same [`pipeline::uninstall_commands`] and
/// [`pipeline::route`] the run uses.
pub fn route_info(entry: &InventoryEntry, sources: Sources<'_>) -> Result<RouteInfo, ErrorObject> {
    let env = sources.sys.env().unwrap_or_default();
    let commands = pipeline::uninstall_commands(entry, &env);
    let command = commands
        .command_line()
        .or_else(|| commands.quiet_command_line())
        .ok_or_else(|| {
            ErrorObject::runtime(format!("{} has no uninstall command", entry.display_name))
        })?;
    let quiet_command = commands.quiet_command_line();
    let signer = [commands.command.as_ref(), commands.quiet.as_ref()]
        .into_iter()
        .flatten()
        .find_map(|command| sources.fs.signer_cn(&command.exe).ok().flatten());
    let processes = sources.sys.processes().unwrap_or_default();
    let running = running_under(&processes, &running_roots(entry, &commands));
    Ok(RouteInfo {
        route: pipeline::route(entry, sources.fs, &env),
        command,
        quiet_command,
        signer,
        running,
    })
}

/// The directories a running process must be under to count as the program's own: its
/// `InstallLocation`, and the directory of each command the entry names.
fn running_roots(entry: &InventoryEntry, commands: &pipeline::UninstallCommands) -> Vec<String> {
    let mut roots: Vec<String> = Vec::new();
    let mut push = |root: String| {
        let root = root.trim_end_matches(['\\', '/']).to_owned();
        if !root.is_empty() && !roots.iter().any(|r| r.eq_ignore_ascii_case(&root)) {
            roots.push(root);
        }
    };
    if let Some(location) = entry.install_location.as_deref() {
        push(location.to_owned());
    }
    for command in [commands.command.as_ref(), commands.quiet.as_ref()]
        .into_iter()
        .flatten()
    {
        if let Some(parent) = Path::new(&command.exe).parent() {
            push(parent.to_string_lossy().into_owned());
        }
    }
    roots
}

/// Processes whose image lies under one of `roots` (case-insensitive, like the rest of the paths).
fn running_under(processes: &[ProcessInfo], roots: &[String]) -> Vec<RunningProcess> {
    if roots.is_empty() {
        return Vec::new();
    }
    processes
        .iter()
        .filter(|process| {
            process
                .path
                .as_deref()
                .is_some_and(|path| roots.iter().any(|root| is_under(path, root)))
        })
        .map(|process| RunningProcess {
            pid: process.pid,
            name: process.name.clone(),
        })
        .collect()
}

/// `path` is `root` or lies below it; `\` and `/` are the same and case is ignored.
fn is_under(path: &str, root: &str) -> bool {
    let path = path.replace('/', "\\").to_ascii_lowercase();
    let root = root
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    path == root || path.starts_with(&format!("{root}\\"))
}

fn gone_program(_program_id: &ProgramId) -> ErrorObject {
    ErrorObject::server(ErrorData::Gone {
        id: IdKind::Program,
    })
}

// ---------------------------------------------------------------------------------------------------------
// uninstall.run_user
// ---------------------------------------------------------------------------------------------------------

/// Runs a medium-route uninstaller at the engine's own level and reports one `uninstall.progress` per
/// pipeline line.
///
/// The order of the checks is the order of the rules: the route first (`wrong_route` for a
/// broker-route program), then the level rule, then the command. The command is exactly the one
/// [`route_info`] shows for the same `quiet` choice, passed to
/// [`pipeline::uninstall_with_command`] so the Job object runs it verbatim.
pub fn handle_run_user(
    request: RequestId,
    params: &RunUserParams,
    sources: Sources<'_>,
    host: &mut dyn ProcessHost,
    level: &Level,
    options: &RunOptions,
    notify: &mut dyn Notify,
) -> Result<RunUserResult, ErrorObject> {
    let inventory = pipeline::inventory(sources);
    let entry = inventory
        .doc
        .entry(&params.program_id)
        .ok_or_else(|| gone_program(&params.program_id))?;
    let env = sources.sys.env().unwrap_or_default();
    let route = pipeline::route(entry, sources.fs, &env);
    if route != Route::Medium {
        return Err(ErrorObject::server(ErrorData::WrongRoute { route }));
    }
    level.check()?;

    let commands = pipeline::uninstall_commands(entry, &env);
    let command = if params.quiet {
        commands.quiet.clone()
    } else {
        commands.command.clone()
    };
    let command = command.ok_or_else(|| {
        ErrorObject::runtime(format!(
            "{} has no {} uninstall command",
            entry.display_name,
            if params.quiet { "quiet" } else { "interactive" }
        ))
    })?;

    let mut done = 0u64;
    let mut notify_error: Option<FrameError> = None;
    let program_id = params.program_id.clone();
    let mut progress = |line: &str| {
        done += 1;
        if notify_error.is_none() {
            let notification = ServerNotification::UninstallProgress(Progress {
                request,
                program_id: Some(program_id.clone()),
                phase: line.to_owned(),
                done,
                total: None,
            });
            if let Err(error) = notify.notify(&notification) {
                notify_error = Some(error);
            }
        }
    };
    let result = pipeline::uninstall_with_command(
        sources,
        host,
        &params.program_id.to_string(),
        None,
        options,
        &command,
        &mut progress,
    );
    drop(progress);
    if let Some(error) = notify_error {
        return Err(ErrorObject::runtime(format!(
            "cannot send uninstall.progress: {error}"
        )));
    }
    let uninstalled = match result {
        Ok(uninstalled) => uninstalled,
        Err(PipelineError::Precondition(message) | PipelineError::Runtime(message)) => {
            return Err(ErrorObject::runtime(message));
        }
    };
    Ok(RunUserResult {
        exit_code: uninstalled.report.doc.exit_code,
        outcome: uninstalled.report.doc.outcome,
    })
}

// ---------------------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use purge_inventory::quiet::QuietCommand;
    use purge_model::{InstallScope, InstallerKind, RawFlags, View, WritableBy};
    use purge_source::fixture::Fixture;
    use purge_source::system::SystemSource;

    const USER: &str = "S-1-5-21-1-2-3-1001";

    fn entry(
        key: &str,
        hive_sid: Option<&str>,
        writable_by: WritableBy,
        uninstall: Option<&str>,
        quiet: Option<&str>,
    ) -> InventoryEntry {
        let program_id = match hive_sid {
            Some(sid) => ProgramId::user(sid, View::K64, key),
            None => ProgramId::machine(View::K64, key),
        }
        .expect("program id");
        InventoryEntry {
            key_path: program_id.key_path(),
            program_id,
            hive_sid: hive_sid.map(str::to_owned),
            view: View::K64,
            display_name: key.to_owned(),
            version: None,
            publisher: None,
            flags: RawFlags {
                has_display_name: true,
                ..RawFlags::default()
            },
            installer_kind: InstallerKind::Unknown,
            scope: if hive_sid.is_some() {
                InstallScope::User
            } else {
                InstallScope::Machine
            },
            product_code: None,
            upgrade_code: None,
            inno_app_id: None,
            writable_by,
            install_location: None,
            uninstall_string: uninstall.map(str::to_owned),
            quiet_uninstall_string: quiet.map(str::to_owned),
            display_icon: None,
            install_time_evidence: Vec::new(),
            msi: None,
        }
    }

    /// Admin-only `C:\Program Files`, user-writable `%LOCALAPPDATA%`; the fixture's default roots
    /// (Program Files, Program Files (x86), SystemRoot) would otherwise hide the difference.
    fn machine() -> Fixture {
        Fixture::builder()
            .admin_only_roots(&[r"C:\Program Files"])
            .dir(r"C:\Program Files\App")
            .file(r"C:\Program Files\App\unins000.exe", 4096)
            .file(r"C:\Program Files\App\unins000.dat", 1024)
            .dir(r"C:\Users\tester\AppData\Local\App")
            .file(r"C:\Users\tester\AppData\Local\App\unins000.exe", 4096)
            .file(r"C:\Users\tester\AppData\Local\App\unins000.dat", 1024)
            .build()
    }

    #[test]
    fn route_table_on_fixtures() {
        let fs = machine();
        let env = std::collections::BTreeMap::new();
        let cases = [
            (
                "an HKU entry stays medium even when its path is admin-only",
                entry(
                    "App_is1",
                    Some(USER),
                    WritableBy::Admin,
                    Some(r#""C:\Program Files\App\unins000.exe""#),
                    None,
                ),
                Route::Medium,
            ),
            (
                "a machine entry whose path a user can write is medium",
                entry(
                    "App_is1",
                    None,
                    WritableBy::Admin,
                    Some(r#""C:\Users\tester\AppData\Local\App\unins000.exe""#),
                    None,
                ),
                Route::Medium,
            ),
            (
                "a machine entry with admin-only ancestors is broker",
                entry(
                    "App_is1",
                    None,
                    WritableBy::Admin,
                    Some(r#""C:\Program Files\App\unins000.exe""#),
                    None,
                ),
                Route::Broker,
            ),
            (
                "a user-writable Uninstall key is medium",
                entry(
                    "App_is1",
                    None,
                    WritableBy::User,
                    Some(r#""C:\Program Files\App\unins000.exe""#),
                    None,
                ),
                Route::Medium,
            ),
            (
                "one user-writable quiet command keeps the entry medium",
                entry(
                    "App_is1",
                    None,
                    WritableBy::Admin,
                    Some(r#""C:\Program Files\App\unins000.exe""#),
                    Some(r#""C:\Users\tester\AppData\Local\App\unins000.exe" /S"#),
                ),
                Route::Medium,
            ),
        ];
        for (what, entry, expected) in cases {
            assert_eq!(pipeline::route(&entry, &fs, &env), expected, "{what}");
        }
    }

    fn facts(user: &str, elevated: bool) -> TokenFacts {
        TokenFacts {
            user_sid: user.to_owned(),
            elevated,
            elevation_type: if elevated {
                token::ElevationType::Full
            } else {
                token::ElevationType::Limited
            },
            integrity_rid: if elevated {
                token::INTEGRITY_HIGH
            } else {
                token::INTEGRITY_MEDIUM
            },
        }
    }

    #[test]
    fn level_rule_with_faked_token_facts() {
        let medium = Level {
            engine: facts(USER, false),
            shell: Some(facts(USER, false)),
        };
        assert!(medium.check().is_ok());

        let uac_off = Level {
            engine: facts(USER, true),
            shell: Some(facts(USER, true)),
        };
        assert!(uac_off.check().is_ok(), "with UAC off both halves elevate");

        let elevated_above_user = Level {
            engine: facts(USER, true),
            shell: Some(facts(USER, false)),
        };
        let error = elevated_above_user.check().unwrap_err();
        let Some(ErrorData::Runtime { message }) = &error.data else {
            panic!("expected a runtime error, got {:?}", error.data);
        };
        assert!(message.contains("start Purge normally"), "{message}");

        let other_user = Level {
            engine: facts("S-1-5-21-1-2-3-2002", false),
            shell: Some(facts(USER, false)),
        };
        assert!(other_user.check().is_err());

        let no_shell = Level {
            engine: facts(USER, false),
            shell: None,
        };
        assert!(no_shell.check().is_err());
    }

    #[test]
    fn run_user_refuses_a_broker_route_program() {
        const KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Broker App";
        let fixture = Fixture::builder()
            .admin_only_roots(&[r"C:\Program Files"])
            .dir(r"C:\Program Files\App")
            .file(r"C:\Program Files\App\unins000.exe", 4096)
            .file(r"C:\Program Files\App\unins000.dat", 1024)
            .sz(KEY, "DisplayName", "Broker App")
            .sz(
                KEY,
                "UninstallString",
                r#""C:\Program Files\App\unins000.exe""#,
            )
            .sz(
                KEY,
                "QuietUninstallString",
                r#""C:\Program Files\App\unins000.exe" /S"#,
            )
            .build();
        let sources = Sources::of(&fixture);
        let program_id = ProgramId::machine(View::K64, "Broker App").expect("program id");
        let params = ProgramParams {
            program_id: program_id.clone(),
        };
        let info = handle_route(&params, sources).expect("route");
        assert_eq!(info.route, Route::Broker);
        assert_eq!(
            info.quiet_command.as_deref(),
            Some(r#""C:\Program Files\App\unins000.exe" /S"#)
        );

        let mut host = purge_inventory::runner::LiveHost::new();
        let level = Level {
            engine: facts(USER, false),
            shell: Some(facts(USER, false)),
        };
        let mut sink = PanicSink;
        let error = handle_run_user(
            RequestId(1),
            &RunUserParams {
                program_id,
                quiet: true,
            },
            sources,
            &mut host,
            &level,
            &RunOptions::default(),
            &mut sink,
        )
        .expect_err("a broker-route program is refused");
        assert_eq!(
            error.data,
            Some(ErrorData::WrongRoute {
                route: Route::Broker
            })
        );
    }

    /// A notification sink that panics: these tests never reach a progress line.
    struct PanicSink;

    impl Notify for PanicSink {
        fn notify(&mut self, notification: &ServerNotification) -> Result<(), FrameError> {
            panic!("unexpected notification {notification:?}");
        }
    }

    #[test]
    fn the_shown_command_is_the_command_run() {
        let fixture = machine();
        let env = fixture.env().expect("environment");
        let entry = entry(
            "App_is1",
            None,
            WritableBy::Admin,
            Some(r#""C:\Users\tester\AppData\Local\App\unins000.exe" /interactive"#),
            Some(r#""C:\Users\tester\AppData\Local\App\unins000.exe" /S"#),
        );
        let commands = pipeline::uninstall_commands(&entry, &env);
        let interactive: QuietCommand = commands.command.clone().expect("interactive command");
        let quiet: QuietCommand = commands.quiet.clone().expect("quiet command");
        assert_eq!(
            interactive.to_command_line(),
            commands.command_line().expect("shown interactive")
        );
        assert_eq!(
            quiet.to_command_line(),
            commands.quiet_command_line().expect("shown quiet")
        );
        // The run passes exactly this `QuietCommand` to `pipeline::uninstall_with_command`, whose
        // runner expands it once more with the same environment; the line therefore does not change.
        assert_eq!(
            interactive.expand(&env).to_command_line(),
            interactive.to_command_line()
        );
        assert_eq!(
            quiet.expand(&env).to_command_line(),
            quiet.to_command_line()
        );

        let info = route_info(&entry, Sources::of(&fixture)).expect("route info");
        assert_eq!(info.command, interactive.to_command_line());
        assert_eq!(info.quiet_command, Some(quiet.to_command_line()));
    }
}
