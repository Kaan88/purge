//! Fault points for crash tests (ENGINE_PLAN.md §10.2, crash injection), active only with the
//! `fault-inject` feature (M2-X-JOURNAL).
//!
//! A fault point is a named place in the executor where the VM rig can make the process die or wait:
//!
//! - `PURGE_FAULT_AT=<point>[:<n>]` aborts the process (`std::process::abort`, no unwinding, no
//!   destructors, no further journal writes) on the `n`-th time `<point>` is hit; `n` counts from 1 and
//!   defaults to 1.
//! - `PURGE_FAULT_PAUSE=<point>:<ms>` sleeps `ms` milliseconds every time `<point>` is hit, so the rig's
//!   race traps can swap something on disk while the executor waits (`intent.flushed:8000`,
//!   `act.before:8000`).
//!
//! Both variables name one point each. When both name the same point, the pause comes first.
//!
//! Every point is declared here, once, as a constant listed in [`FAULT_POINTS`]; `purge-engine journal
//! fault-points` prints that list and the rig's crash matrix iterates it. Code anywhere in the crate hits
//! a point with [`point`], passing the constant or the same literal (`fault::point("intent.flushed")`); a
//! unit test scans the crate's sources and fails if a literal names an undeclared point. To add a point,
//! add a constant, list it in [`FAULT_POINTS`] and describe it in [`describe`].
//!
//! Without the `fault-inject` feature [`point`] is an empty inline function: it reads no environment
//! variable and compiles to nothing. Release builds never enable the feature (only `purge-engine`'s
//! `rig-exec` does).

/// The environment variable that makes a fault point abort the process: `<point>[:<n>]`.
pub const ENV_AT: &str = "PURGE_FAULT_AT";

/// The environment variable that makes a fault point pause: `<point>:<ms>`.
pub const ENV_PAUSE: &str = "PURGE_FAULT_PAUSE";

/// The longest pause [`ENV_PAUSE`] accepts, in milliseconds (ten minutes).
pub const MAX_PAUSE_MS: u64 = 600_000;

/// Whether fault points do anything in this build (the `fault-inject` feature).
pub const ENABLED: bool = cfg!(feature = "fault-inject");

/// After the journal header is written and flushed, before any `validated` record (journal).
pub const JOURNAL_HEADER: &str = "journal.header";
/// After a backup or definition file is written and flushed, before it is read back.
pub const BACKUP_WRITTEN: &str = "backup.written";
/// After a backup was read back and hashed, before the intent that names it is written.
pub const BACKUP_VERIFIED: &str = "backup.verified";
/// After an `intent` record is flushed, before the token reaches the caller (journal). The race traps
/// pause here.
pub const INTENT_FLUSHED: &str = "intent.flushed";
/// Just before the action runs on the handle the gate inspected. The race traps pause here.
pub const ACT_BEFORE: &str = "act.before";
/// After the action ran, before it is verified and its `done` record written.
pub const ACT_AFTER: &str = "act.after";
/// Before a `done` record is written, with or without an intent before it (journal).
pub const DONE_BEFORE: &str = "done.before";
/// After a `group_end` record is written and flushed (journal).
pub const GROUP_END: &str = "group.end";
/// Before the `commit` record is written, after the last group was closed (journal).
pub const COMMIT_BEFORE: &str = "commit.before";
/// In the middle of a key-tree delete: some keys of the tree are gone, others remain.
pub const REGDELETE_MID: &str = "regdelete.mid";
/// In the middle of a key-tree restore: some keys are back, others are not.
pub const REGRESTORE_MID: &str = "regrestore.mid";
/// After an `undo_intent` record is flushed, before the inverse runs (journal).
pub const UNDO_INTENT: &str = "undo.intent";
/// After an inverse ran, before its `undo_done` record is written.
pub const UNDO_ACT_AFTER: &str = "undo.act.after";
/// After the new session index is written to its temporary file, before the rename over the old one.
pub const INDEX_WRITE: &str = "index.write";
/// In the middle of an expiry delete walk.
pub const EXPIRY_MID: &str = "expiry.mid";
/// After a boot-time move is registered, before its `done` record is written.
pub const BOOTMOVE_REGISTERED: &str = "bootmove.registered";

/// Every fault point, in the order a run meets them. `purge-engine journal fault-points` prints this list.
pub const FAULT_POINTS: &[&str] = &[
    JOURNAL_HEADER,
    BACKUP_WRITTEN,
    BACKUP_VERIFIED,
    INTENT_FLUSHED,
    ACT_BEFORE,
    ACT_AFTER,
    DONE_BEFORE,
    GROUP_END,
    COMMIT_BEFORE,
    REGDELETE_MID,
    REGRESTORE_MID,
    UNDO_INTENT,
    UNDO_ACT_AFTER,
    INDEX_WRITE,
    EXPIRY_MID,
    BOOTMOVE_REGISTERED,
];

/// Whether `name` is a declared fault point.
pub fn is_point(name: &str) -> bool {
    FAULT_POINTS.contains(&name)
}

/// One line on where a fault point sits, for `journal fault-points`; `None` for an undeclared name.
pub fn describe(name: &str) -> Option<&'static str> {
    Some(match name {
        JOURNAL_HEADER => "journal header written and flushed, nothing validated yet",
        BACKUP_WRITTEN => "backup file written and flushed, not yet read back",
        BACKUP_VERIFIED => "backup read back and hashed, intent not yet written",
        INTENT_FLUSHED => "intent flushed, action not yet started",
        ACT_BEFORE => "about to act on the gated handle",
        ACT_AFTER => "action ran, not yet verified, done not yet written",
        DONE_BEFORE => "about to write a done record",
        GROUP_END => "group_end written and flushed",
        COMMIT_BEFORE => "all groups closed, commit not yet written",
        REGDELETE_MID => "key-tree delete half done",
        REGRESTORE_MID => "key-tree restore half done",
        UNDO_INTENT => "undo_intent flushed, inverse not yet started",
        UNDO_ACT_AFTER => "inverse ran, undo_done not yet written",
        INDEX_WRITE => "new session index in its temp file, not yet renamed",
        EXPIRY_MID => "expiry delete walk half done",
        BOOTMOVE_REGISTERED => "boot-time move registered, done not yet written",
        _ => return None,
    })
}

/// Hits the fault point `name`.
///
/// With the `fault-inject` feature: pauses when [`ENV_PAUSE`] names the point, then aborts the process when
/// [`ENV_AT`] names it and this is the hit it counts to. A malformed variable panics on the first hit of
/// any point (call [`check_env`] at start-up to refuse it earlier). Without the feature this does nothing
/// and compiles to nothing.
#[inline(always)]
pub fn point(name: &'static str) {
    #[cfg(feature = "fault-inject")]
    active::hit(name);
    #[cfg(not(feature = "fault-inject"))]
    let _ = name;
}

/// Checks [`ENV_AT`] and [`ENV_PAUSE`]: both must be unset, empty or well formed and name a declared point.
/// Without the `fault-inject` feature the variables mean nothing and this always succeeds.
pub fn check_env() -> Result<(), FaultEnvError> {
    #[cfg(feature = "fault-inject")]
    {
        active::config().as_ref().map(|_| ()).map_err(Clone::clone)
    }
    #[cfg(not(feature = "fault-inject"))]
    {
        Ok(())
    }
}

/// Why a fault environment variable was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FaultEnvError {
    /// The variable is not valid Unicode.
    #[error("{var} is not valid Unicode")]
    NotUnicode {
        /// The variable.
        var: &'static str,
    },
    /// The variable names a point that is not declared.
    #[error("{var} names {name:?}, which is not a fault point")]
    UnknownPoint {
        /// The variable.
        var: &'static str,
        /// The name it gave.
        name: String,
    },
    /// The number after the point is missing, not a number, or out of range.
    #[error("{var} has a bad number {text:?} (expected {expected})")]
    BadNumber {
        /// The variable.
        var: &'static str,
        /// The text after the `:`.
        text: String,
        /// What was expected.
        expected: &'static str,
    },
}

/// Reads `PURGE_FAULT_AT`'s value: `<point>[:<n>]`, `n >= 1`.
#[cfg(any(feature = "fault-inject", test))]
fn parse_at(text: &str) -> Result<(&'static str, u32), FaultEnvError> {
    let (name, nth) = match text.split_once(':') {
        Some((name, nth)) => {
            let n = nth.parse::<u32>().ok().filter(|&n| n >= 1).ok_or_else(|| {
                FaultEnvError::BadNumber {
                    var: ENV_AT,
                    text: nth.to_owned(),
                    expected: "a hit count of 1 or more",
                }
            })?;
            (name, n)
        }
        None => (text, 1),
    };
    Ok((declared(ENV_AT, name)?, nth))
}

/// Reads `PURGE_FAULT_PAUSE`'s value: `<point>:<ms>`, `ms <= MAX_PAUSE_MS`.
#[cfg(any(feature = "fault-inject", test))]
fn parse_pause(text: &str) -> Result<(&'static str, u64), FaultEnvError> {
    let (name, ms) = text.split_once(':').unwrap_or((text, ""));
    let ms = ms
        .parse::<u64>()
        .ok()
        .filter(|&ms| ms <= MAX_PAUSE_MS)
        .ok_or_else(|| FaultEnvError::BadNumber {
            var: ENV_PAUSE,
            text: ms.to_owned(),
            expected: "milliseconds from 0 to 600000",
        })?;
    Ok((declared(ENV_PAUSE, name)?, ms))
}

/// The declared point spelled `name`.
#[cfg(any(feature = "fault-inject", test))]
fn declared(var: &'static str, name: &str) -> Result<&'static str, FaultEnvError> {
    FAULT_POINTS
        .iter()
        .copied()
        .find(|&point| point == name)
        .ok_or_else(|| FaultEnvError::UnknownPoint {
            var,
            name: name.to_owned(),
        })
}

#[cfg(feature = "fault-inject")]
mod active {
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use super::{ENV_AT, ENV_PAUSE, FaultEnvError, is_point, parse_at, parse_pause};

    /// The fault configuration of this process, read once from the environment.
    pub(super) struct Config {
        /// The point that aborts, and on which hit.
        at: Option<(&'static str, u32)>,
        /// The point that pauses, and for how long.
        pause: Option<(&'static str, u64)>,
    }

    static CONFIG: OnceLock<Result<Config, FaultEnvError>> = OnceLock::new();
    /// Hits of the point named by `PURGE_FAULT_AT` so far.
    static HITS: AtomicU32 = AtomicU32::new(0);

    /// Reads one variable: `None` when unset or empty.
    fn var(name: &'static str) -> Result<Option<String>, FaultEnvError> {
        match std::env::var(name) {
            Ok(text) if text.is_empty() => Ok(None),
            Ok(text) => Ok(Some(text)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(FaultEnvError::NotUnicode { var: name }),
        }
    }

    fn read() -> Result<Config, FaultEnvError> {
        Ok(Config {
            at: var(ENV_AT)?.as_deref().map(parse_at).transpose()?,
            pause: var(ENV_PAUSE)?.as_deref().map(parse_pause).transpose()?,
        })
    }

    pub(super) fn config() -> &'static Result<Config, FaultEnvError> {
        CONFIG.get_or_init(read)
    }

    pub(super) fn hit(name: &'static str) {
        debug_assert!(is_point(name), "undeclared fault point {name:?}");
        let config = match config() {
            Ok(config) => config,
            Err(e) => panic!("fault injection misconfigured: {e}"),
        };
        if let Some((point, ms)) = config.pause {
            if point == name {
                eprintln!("purge: fault point {name}: pausing {ms} ms");
                std::thread::sleep(Duration::from_millis(ms));
            }
        }
        if let Some((point, nth)) = config.at {
            if point == name {
                let hit = HITS.fetch_add(1, Ordering::SeqCst).saturating_add(1);
                if hit == nth {
                    eprintln!("purge: fault point {name}: hit {hit}, aborting");
                    std::process::abort();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn points_are_unique_described_and_well_formed() {
        assert_eq!(FAULT_POINTS.len(), 16);
        for (i, name) in FAULT_POINTS.iter().enumerate() {
            assert!(!FAULT_POINTS[..i].contains(name), "duplicate {name}");
            assert!(describe(name).is_some(), "{name} has no description");
            assert!(is_point(name));
            assert!(
                name.split('.')
                    .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_lowercase())),
                "{name}"
            );
        }
        assert!(!is_point("intent"));
        assert!(describe("nowhere").is_none());
        // The names the rig's race traps use (docs/M2_DESIGN.json, cross-package notes).
        assert!(is_point("intent.flushed") && is_point("act.before"));
        assert_eq!(ENABLED, cfg!(feature = "fault-inject"));
    }

    #[test]
    fn env_values_parse_strictly() {
        assert_eq!(parse_at("intent.flushed"), Ok((INTENT_FLUSHED, 1)));
        assert_eq!(parse_at("act.before:3"), Ok((ACT_BEFORE, 3)));
        for bad in [
            "act.before:0",
            "act.before:",
            "act.before:x",
            "act.before:-1",
        ] {
            assert!(
                matches!(parse_at(bad), Err(FaultEnvError::BadNumber { .. })),
                "{bad}"
            );
        }
        assert!(matches!(
            parse_at("act.never"),
            Err(FaultEnvError::UnknownPoint { .. })
        ));
        assert!(matches!(
            parse_at("Act.Before"),
            Err(FaultEnvError::UnknownPoint { .. })
        ));
        assert_eq!(
            parse_pause("intent.flushed:8000"),
            Ok((INTENT_FLUSHED, 8000))
        );
        assert_eq!(parse_pause("act.before:0"), Ok((ACT_BEFORE, 0)));
        for bad in [
            "act.before",
            "act.before:",
            "act.before:600001",
            "act.before:1.5",
        ] {
            assert!(
                matches!(parse_pause(bad), Err(FaultEnvError::BadNumber { .. })),
                "{bad}"
            );
        }
        assert!(matches!(
            parse_pause("nowhere:5"),
            Err(FaultEnvError::UnknownPoint { .. })
        ));
        assert!(!parse_at("x").unwrap_err().to_string().is_empty());
    }

    /// Every string literal passed to `point` anywhere in the crate's sources names a declared point, so
    /// `journal fault-points` lists every point the code can hit.
    #[test]
    fn every_literal_point_in_the_crate_is_declared() {
        fn scan(dir: &Path, found: &mut Vec<(PathBuf, String)>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    scan(&path, found);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    let mut rest = text.as_str();
                    while let Some(at) = rest.find("point(\"") {
                        // `point(` itself, not `is_point(` or another name ending in it.
                        let call = !rest[..at]
                            .chars()
                            .next_back()
                            .is_some_and(|c| c.is_alphanumeric() || c == '_');
                        rest = &rest[at + "point(\"".len()..];
                        let end = rest.find('"').unwrap_or(rest.len());
                        if call {
                            found.push((path.clone(), rest[..end].to_owned()));
                        }
                    }
                }
            }
        }
        let mut found = Vec::new();
        scan(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut found,
        );
        for (file, name) in &found {
            assert!(
                is_point(name),
                "{} hits undeclared fault point {name:?}",
                file.display()
            );
        }
    }

    #[test]
    fn check_env_accepts_the_test_environment() {
        // The test process runs without fault variables (the child-process tests set them only for the
        // child), so the check passes with the feature on and off.
        if std::env::var_os(ENV_AT).is_none() && std::env::var_os(ENV_PAUSE).is_none() {
            assert_eq!(check_env(), Ok(()));
        }
    }

    /// Set only in a child process of the test binary: a directory the child marks its progress in.
    const CHILD_DIR: &str = "PURGE_TEST_FAULT_CHILD_DIR";

    /// The child half of the process tests: hits `act.before` three times, leaving a marker file before
    /// each hit. Does nothing when run as an ordinary test.
    #[test]
    fn child_hits_act_before_three_times() {
        let Some(dir) = std::env::var_os(CHILD_DIR) else {
            return;
        };
        let dir = PathBuf::from(dir);
        for n in 1..=3 {
            std::fs::write(dir.join(format!("hit-{n}")), b"").unwrap();
            point(ACT_BEFORE);
        }
        std::fs::write(dir.join("finished"), b"").unwrap();
    }

    /// Runs [`child_hits_act_before_three_times`] in a child process with `env` set; returns its exit code
    /// and which marker files it left.
    fn run_child(env: &[(&str, &str)]) -> (Option<i32>, Vec<String>) {
        let dir = std::env::temp_dir().join(format!(
            "purge-fault-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "fault::tests::child_hits_act_before_three_times",
                "--test-threads=1",
            ])
            .env(CHILD_DIR, &dir)
            .env_remove(ENV_AT)
            .env_remove(ENV_PAUSE)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        for (key, value) in env {
            command.env(key, value);
        }
        let status = command.status().unwrap();
        let mut markers: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        markers.sort();
        std::fs::remove_dir_all(&dir).unwrap();
        (status.code(), markers)
    }

    /// The exit code of a process ended by `std::process::abort` on Windows (`__fastfail`).
    #[cfg(feature = "fault-inject")]
    const ABORT_CODE: i32 = 0xC000_0409_u32 as i32;

    #[cfg(feature = "fault-inject")]
    #[test]
    fn fault_at_aborts_on_the_nth_hit() {
        let (code, markers) = run_child(&[(ENV_AT, "act.before:2")]);
        assert_eq!(code, Some(ABORT_CODE));
        assert_eq!(markers, ["hit-1", "hit-2"]);

        let (code, markers) = run_child(&[(ENV_AT, "act.before")]);
        assert_eq!(code, Some(ABORT_CODE));
        assert_eq!(markers, ["hit-1"]);

        // Another point, or a count beyond the hits, never fires.
        let (code, markers) = run_child(&[(ENV_AT, "act.after")]);
        assert_eq!(code, Some(0));
        assert_eq!(markers, ["finished", "hit-1", "hit-2", "hit-3"]);
        let (code, _) = run_child(&[(ENV_AT, "act.before:4")]);
        assert_eq!(code, Some(0));
    }

    #[cfg(feature = "fault-inject")]
    #[test]
    fn fault_pause_waits_on_every_hit() {
        let started = std::time::Instant::now();
        let (code, markers) = run_child(&[(ENV_PAUSE, "act.before:150")]);
        assert_eq!(code, Some(0));
        assert_eq!(markers, ["finished", "hit-1", "hit-2", "hit-3"]);
        assert!(started.elapsed() >= std::time::Duration::from_millis(450));
    }

    #[cfg(feature = "fault-inject")]
    #[test]
    fn malformed_fault_variable_fails_the_first_hit() {
        // A panic, not an abort: the rig must not mistake a typo for an injected crash.
        let (code, markers) = run_child(&[(ENV_AT, "act.befor")]);
        assert_eq!(code, Some(101));
        assert_eq!(markers, ["hit-1"]);
    }

    #[cfg(not(feature = "fault-inject"))]
    #[test]
    fn without_the_feature_points_do_nothing() {
        let (code, markers) = run_child(&[(ENV_AT, "act.before"), (ENV_PAUSE, "act.before:5000")]);
        assert_eq!(code, Some(0));
        assert_eq!(markers, ["finished", "hit-1", "hit-2", "hit-3"]);
    }
}
