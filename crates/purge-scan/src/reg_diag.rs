//! Scanner REG-DIAG (ENGINE_PLAN.md §5.6; M1b package M1B-S-DIAG): diagnostic registrations the removed
//! app left behind: its RAS tracing keys and its event-log sources.
//!
//! # Tracing
//!
//! Windows' RAS client writes one key per program that loads it, named after the program's file stem:
//! `HKLM\SOFTWARE\Microsoft\Tracing\<stem>_RASAPI32` and `..._RASMANCS`, and the same below
//! `HKLM\SOFTWARE\WOW6432Node\Microsoft\Tracing` for a 32-bit program. Each of the two `Tracing` keys
//! is listed once (`subkeys()`); a subkey is the app's when its name, without the suffix, equals the file
//! stem of one of the app's exes (`fp.exes`, `.exe` files only), compared ignoring case and whole (`7z`
//! is not `7zFM`).
//!
//! That is a name and nothing else, so the candidate is at most Likely: `ChainedRef` to the exe, lowered
//! to Tier B. It is not emitted at all when:
//!
//! - the stem is a generic word (`kb/generic-tokens.json`, plus [`GENERIC_STEMS`]: `setup`, the Inno
//!   uninstaller's `unins000`, ...) or the exe is one of the app's recorded uninstallers: such a name is
//!   every installer's;
//! - another installed app has an exe of that stem ([`OtherApps`](crate::framework::OtherApps): its exe
//!   anchors and the `.exe` files its records name; R3a S5: a component of another installed MSI
//!   product whose file key path is `<stem>.exe`; a service, task or firewall program `<stem>.exe`
//!   outside the app's roots);
//! - `App Paths\<stem>.exe` (the machine's, both views, or the scan user's) exists and its default is
//!   not a path in the app's roots or one of its files, or cannot be read (R3a S5);
//! - the clean Windows of this build has the key (Windows' own program of that name).
//!
//! The `Tracing` keys themselves are never candidates (guard rule `reg.tracing-root`).
//!
//! # Event-log sources
//!
//! `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<log>\<source>`. A source is looked at when
//!
//! - a hit of the one reference walk of the pipeline ([`ScanCtx::ref_hits_under`]) is its
//!   `EventMessageFile`, `CategoryMessageFile` or `ParameterMessageFile` value naming a file of the app
//!   (by path, never by a bare file name), or
//! - one of the app's MSI products has a whole-key `Registry` row on exactly that key.
//!
//! Each log holding such a source is listed once (`subkeys()`, which also gives the source's name as
//! stored); the source's values are read once. The source is offered whole (`DeleteKey`) only when
//!
//! - it has an `EventMessageFile`, and every file of every message-file value (each value split at `;`,
//!   `%NAME%` expanded) is inside an InstallRoot of the app or one of its exe or outside-root files. A
//!   source with one file outside (a Windows or .NET message DLL, whatever the source is called) is not
//!   the app's: no candidate;
//! - the clean Windows of this build does not have it.
//!
//! Evidence: `ChainedRef` (Key scope) to the app's message file, and `InstallerManifest(Msi)` for the
//! app's MSI row. It may be Safe only with the MSI row **and** every message file proven absent; otherwise
//! all its evidence is lowered to Tier B: Likely. A message file inside another app's root, or one
//! another app's records name, blocks it (`InsideOtherApp`, `ReferencedByOtherApp`).
//!
//! The log keys are never candidates (guard rule `reg.eventlog-log`); neither is anything deeper than a
//! source. `WINEVT\Publishers` and ETW providers are M4.
//!
//! # Reads
//!
//! One `subkeys()` of each `Tracing` key; when a tracing key matched, one `subkeys()` of each of the three
//! `App Paths` keys and one `value()` per `App Paths\<stem>.exe` found; one `subkeys()` per log holding a
//! source looked at; per source one `values()`. The common blockers add one `key_info()` per candidate.
//!
//! # Missing data
//!
//! A key that cannot be read (`AccessDenied`, `NotCaptured`) or a value not read in full makes no
//! candidate and one scan warning (`ScanExt::warn`); "not there" is no warning.

use std::collections::HashSet;

use purge_guard::canon::canon_path;
use purge_guard::prefix::{self, Relation};
use purge_identity::kbdata::Kb;
use purge_index::sysobj::{Env, ProgramRef, task_programs};
use purge_model::{
    Action, AnchorKind, Blocker, Candidate, Category, EvidenceKind, ManifestKind, Target, Tier,
};
use purge_source::types::{RegValue, SourceError};

use crate::com_class::warn_unread;
use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};
use crate::fs_installdir::{clean_path, expand_env, has_extension, stem};

/// The scanner's catalog id.
pub const ID: &str = "REG-DIAG";

/// The `Tracing` keys of both registry views.
pub const TRACING_KEYS: [&str; 2] = [
    r"HKLM\SOFTWARE\Microsoft\Tracing",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Tracing",
];

/// The suffixes of a program's tracing keys.
pub const TRACING_SUFFIXES: [&str; 2] = ["_RASAPI32", "_RASMANCS"];

/// The event logs.
pub const EVENTLOG_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog";

/// The values of a source that name its message files.
pub const MESSAGE_FILE_VALUES: [&str; 3] = [
    "EventMessageFile",
    "CategoryMessageFile",
    "ParameterMessageFile",
];

/// File stems too common to name one program, besides the generic tokens of the KB: installers and
/// uninstallers that every product ships under the same name.
pub const GENERIC_STEMS: &[&str] = &[
    "setup",
    "install",
    "installer",
    "uninstall",
    "uninst",
    "update",
    "updater",
    "launcher",
    "helper",
];

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[
    // Both views: a root pattern never spells `WOW6432Node` (`RootSpec`).
    RootSpec::reg(r"HKLM\SOFTWARE\Microsoft\Tracing", Some(1)),
    RootSpec::reg(r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog", Some(2)),
];

/// The REG-DIAG scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegDiag;

impl Scanner for RegDiag {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
        let mut out = Vec::new();
        tracing_keys(ctx, &mut out);
        event_sources(ctx, &mut out);
        out
    }
}

// ---------------------------------------------------------------------------------------------------------
// Tracing
// ---------------------------------------------------------------------------------------------------------

/// The stem a tracing key is named after (`7zFM` of `7zFM_RASAPI32`); `None` for any other name.
pub fn tracing_stem(name: &str) -> Option<&str> {
    TRACING_SUFFIXES.iter().find_map(|suffix| {
        let cut = name.len().checked_sub(suffix.len())?;
        (cut > 0 && name.is_char_boundary(cut) && name[cut..].eq_ignore_ascii_case(suffix))
            .then(|| &name[..cut])
    })
}

/// Whether a file stem is too common to name one program: a generic token of the KB, one of
/// [`GENERIC_STEMS`], or the Inno uninstaller's `unins` followed by digits.
pub fn generic_stem(stem: &str) -> bool {
    let folded = prefix::fold(stem.trim());
    if folded.is_empty()
        || Kb::shipped().generic.contains(&folded)
        || GENERIC_STEMS.contains(&folded.as_str())
    {
        return true;
    }
    folded
        .strip_prefix("unins")
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether another installed app has an exe whose file stem is `stem`, from what the scan already holds
/// (R3a S5 widened the rule beyond the other apps' records):
///
/// - another installed app's exe anchors and the `.exe` files its records name
///   ([`OtherApps`](crate::framework::OtherApps));
/// - a file key path `<stem>.exe` of a component that an installed MSI product other than the app's
///   is a client of (the ownership index);
/// - a service's, a scheduled task's or a firewall rule's program `<stem>.exe` that is not the app's
///   (outside its roots, not one of its files; the system-object index).
fn stem_of_other_app(ctx: &ScanCtx<'_>, stem_text: &str) -> bool {
    let same = |file: &str| {
        let name = prefix::leaf(file).unwrap_or(file);
        has_extension(name, &["exe"]) && prefix::eq_ci(stem(name), stem_text)
    };
    let records = ctx.other_apps.apps().iter().any(|app| {
        app.anchors
            .iter()
            .any(|a| a.kind == AnchorKind::Exe && same(&a.text))
            || app.files.iter().any(|f| same(f))
    });
    records || msi_file_of_other_product(ctx, stem_text) || system_object_program(ctx, &same)
}

/// Whether an installed MSI product other than the app's owns a component whose file key path is
/// `<stem>.exe`.
fn msi_file_of_other_product(ctx: &ScanCtx<'_>, stem_text: &str) -> bool {
    let ix = &ctx.ext.ownership;
    let own = |client: &str| {
        ctx.fp
            .msi
            .iter()
            .any(|m| prefix::eq_ci(m.packed_code.trim(), client.trim()))
    };
    ix.files_named(&format!("{stem_text}.exe"))
        .iter()
        .flat_map(|(_, owners)| owners.iter())
        .flat_map(|owner| owner.clients.iter())
        .any(|client| !own(client) && ix.installed(client).is_some())
}

/// Whether a service, task or firewall rule of the machine runs a program `same` accepts that is not
/// the app's (outside every root of the app and none of its files).
fn system_object_program(ctx: &ScanCtx<'_>, same: &dyn Fn(&str) -> bool) -> bool {
    let index = &ctx.ext.sysobj;
    let foreign = |file: &str| {
        same(file)
            && !ctx
                .fp
                .roots
                .iter()
                .any(|r| prefix::is_inside(file, &r.path))
            && !ctx.is_app_file(file)
    };
    let env = Env::new(ctx.env.iter());
    index
        .services
        .iter()
        .filter_map(|s| s.program.file())
        .any(foreign)
        || index
            .firewall
            .iter()
            .filter_map(|r| r.program.file())
            .any(foreign)
        || index.tasks.iter().any(|t| {
            task_programs(&t.identity, &env)
                .actions
                .iter()
                .filter_map(ProgramRef::file)
                .any(foreign)
        })
}

/// The `App Paths` keys a program name is registered under: the machine's (both views) and the scan
/// user's.
fn app_paths_roots(ctx: &ScanCtx<'_>) -> [String; 3] {
    const APP_PATHS: &str = r"Microsoft\Windows\CurrentVersion\App Paths";
    [
        format!(r"HKLM\SOFTWARE\{APP_PATHS}"),
        format!(r"HKLM\SOFTWARE\WOW6432Node\{APP_PATHS}"),
        format!(r"HKU\{}\Software\{APP_PATHS}", ctx.fp.user_sid.trim()),
    ]
}

/// One `App Paths` key and its subkey names; `Err` for a key that could not be read.
type AppPathsRoot = (String, Result<Vec<String>, ()>);

/// The `App Paths` listings, read on first use: one `subkeys()` per root.
#[derive(Default)]
struct AppPaths {
    roots: Option<Vec<AppPathsRoot>>,
}

impl AppPaths {
    /// Whether `App Paths\<stem>.exe` registers another program (R3a S5): it exists and its default
    /// value is a path outside the app's roots, or cannot be read; or a listing could not be read.
    fn foreign(&mut self, ctx: &ScanCtx<'_>, stem_text: &str) -> bool {
        let roots = self.roots.get_or_insert_with(|| {
            app_paths_roots(ctx)
                .into_iter()
                .map(|root| {
                    let names = match ctx.reg.subkeys(&root) {
                        Ok(names) => Ok(names),
                        Err(SourceError::NotFound) => Ok(Vec::new()),
                        Err(e) => {
                            warn_unread(ctx, ID, &root, &e);
                            Err(())
                        }
                    };
                    (root, names)
                })
                .collect()
        });
        let want = format!("{stem_text}.exe");
        roots.iter().any(|(root, names)| {
            let Ok(names) = names else {
                // An `App Paths` key cannot be read (warned when listed): who else has the name is
                // unknown.
                return true;
            };
            let Some(name) = names.iter().find(|n| prefix::eq_ci(n, &want)) else {
                return false;
            };
            let key = format!(r"{root}\{name}");
            let path = match ctx.reg.value(&key, "") {
                Ok(data) if data.is_complete() => data
                    .string()
                    .and_then(|s| clean_path(&expand_env(&s, ctx.env))),
                _ => None,
            };
            !path.is_some_and(|p| {
                ctx.fp.roots.iter().any(|r| prefix::is_inside(&p, &r.path)) || ctx.is_app_file(&p)
            })
        })
    }
}

/// The app's exes a tracing key may be named after: `(stem, exe path)`, one per stem, without the
/// generic stems, the uninstallers and the stems another app's exe has too.
fn tracing_stems(ctx: &ScanCtx<'_>) -> Vec<(String, String)> {
    let fp = ctx.fp;
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for exe in &fp.exes {
        let Some(name) = prefix::leaf(&exe.path) else {
            continue;
        };
        if !has_extension(name, &["exe"]) {
            continue;
        }
        let stem_text = stem(name);
        if !seen.insert(prefix::fold(stem_text)) {
            continue;
        }
        let uninstaller = fp
            .uninstallers
            .iter()
            .any(|u| prefix::is_same(u, &exe.path));
        if generic_stem(stem_text) || uninstaller || stem_of_other_app(ctx, stem_text) {
            continue;
        }
        out.push((stem_text.to_owned(), exe.path.clone()));
    }
    out
}

/// The tracing keys named after one of the app's exes.
fn tracing_keys(ctx: &ScanCtx<'_>, out: &mut Vec<Candidate>) {
    let stems = tracing_stems(ctx);
    if stems.is_empty() {
        return;
    }
    let mut app_paths = AppPaths::default();
    for root in TRACING_KEYS {
        let names = match ctx.reg.subkeys(root) {
            Ok(names) => names,
            Err(SourceError::NotFound) => continue,
            // The `Tracing` key of this view cannot be read (access denied, not captured): nothing is
            // offered from it.
            Err(e) => {
                warn_unread(ctx, ID, root, &e);
                continue;
            }
        };
        for name in names {
            let Some(key_stem) = tracing_stem(&name) else {
                continue;
            };
            let Some((stem_text, exe)) = stems.iter().find(|(s, _)| prefix::eq_ci(s, key_stem))
            else {
                continue;
            };
            let target = Target::RegKey {
                path: format!(r"{root}\{name}"),
            };
            // Windows has a key of that name: the stem is a Windows program's too.
            if ctx.in_baseline(&target) {
                continue;
            }
            // Another program is registered under the name (R3a S5).
            if app_paths.foreign(ctx, stem_text) {
                continue;
            }
            let mut b = ctx.candidate(ID, target, Action::DeleteKey, Category::Registration);
            b.chained_ref(Tier::A, exe);
            b.cap_at_tier_b("a tracing key is named after the app's exe, and the name is all");
            b.common_blockers();
            out.push(b.build());
        }
    }
}

// ---------------------------------------------------------------------------------------------------------
// Event-log sources
// ---------------------------------------------------------------------------------------------------------

/// A source looked at.
#[derive(Debug, Clone)]
struct Source {
    log: String,
    name: String,
    /// The app's MSI rows that remove exactly this key: `(product code, row)`.
    msi_rows: Vec<(String, String)>,
}

/// The log and source names of `key` when it is exactly `EventLog\<log>\<source>` (any spelling of the
/// current control set); `None` for the log keys, anything deeper and anything elsewhere.
fn log_and_source(ctx: &ScanCtx<'_>, key: &str) -> Option<(String, String)> {
    if ctx.key_relation(key, EVENTLOG_KEY) != Relation::Inside {
        return None;
    }
    let below: Vec<&str> = prefix::segments(key)
        .skip(prefix::segments(EVENTLOG_KEY).count())
        .collect();
    match below.as_slice() {
        [log, source] if !log.is_empty() && !source.is_empty() => {
            Some(((*log).to_owned(), (*source).to_owned()))
        }
        _ => None,
    }
}

/// The sources to look at: those a reference hit names by a message-file value, and those an MSI row of
/// the app removes whole. Each once.
fn sources_looked_at(ctx: &ScanCtx<'_>) -> Vec<Source> {
    let mut out: Vec<Source> = Vec::new();
    let mut add = |log: String, name: String, msi: Option<(String, String)>| {
        let at = out
            .iter()
            .position(|s| prefix::eq_ci(&s.log, &log) && prefix::eq_ci(&s.name, &name));
        let at = at.unwrap_or_else(|| {
            out.push(Source {
                log,
                name,
                msi_rows: Vec::new(),
            });
            out.len() - 1
        });
        if let Some(row) = msi
            && !out[at].msi_rows.contains(&row)
        {
            out[at].msi_rows.push(row);
        }
    };
    // Without the reference walk (`ScanExt::none`) no source is found by its message files; only the
    // app's MSI rows are looked at.
    if ctx.ext.ref_hits_for(&ctx.fp.app.program_id).is_none() {
        ctx.ext.warn(
            ID,
            "the shared reference walk was not run for this app; event-log sources are found by \
             the app's MSI rows only",
        );
    }
    for hit in ctx.ref_hits_under(EVENTLOG_KEY) {
        let message_file = MESSAGE_FILE_VALUES
            .iter()
            .any(|v| prefix::eq_ci(v, &hit.value_name));
        let by_path =
            matches!(hit.anchor.kind, AnchorKind::Root | AnchorKind::Exe) && !hit.name_only;
        if !message_file || !by_path {
            continue;
        }
        if let Some((log, name)) = log_and_source(ctx, &hit.key) {
            add(log, name, None);
        }
    }
    for msi in &ctx.fp.msi {
        for row in msi.registry_rows.iter().filter(|r| r.whole_key) {
            if let Some((log, name)) = log_and_source(ctx, &row.key) {
                add(log, name, Some((msi.product_code.clone(), row.row.clone())));
            }
        }
    }
    out
}

/// The event-log sources of the app.
fn event_sources(ctx: &ScanCtx<'_>, out: &mut Vec<Candidate>) {
    let sources = sources_looked_at(ctx);
    let mut logs: Vec<&str> = Vec::new();
    for source in &sources {
        if !logs.iter().any(|l| prefix::eq_ci(l, &source.log)) {
            logs.push(&source.log);
        }
    }
    for log in logs {
        let log_key = format!(r"{EVENTLOG_KEY}\{log}");
        let names = match ctx.reg.subkeys(&log_key) {
            Ok(names) => names,
            Err(SourceError::NotFound) => continue,
            // The log cannot be listed (access denied, not captured): none of its sources is offered.
            Err(e) => {
                warn_unread(ctx, ID, &log_key, &e);
                continue;
            }
        };
        for source in sources.iter().filter(|s| prefix::eq_ci(&s.log, log)) {
            // The name as stored; a source that is not there any more is not offered.
            let Some(stored) = names.iter().find(|n| prefix::eq_ci(n, &source.name)) else {
                continue;
            };
            out.extend(source_candidate(ctx, &log_key, stored, &source.msi_rows));
        }
    }
}

/// A message file named in a source's value, canonical; `None` when the entry is not one absolute drive
/// path after expansion (relative, UNC, an unknown `%NAME%`, an 8.3 segment the guard cannot vouch for).
fn message_file(ctx: &ScanCtx<'_>, entry: &str) -> Option<String> {
    let expanded = expand_env(entry, ctx.env);
    let clean = clean_path(&expanded)?;
    let canon = canon_path(&clean, ctx.guard, None).ok()?;
    (!canon.needs_long_name).then_some(canon.path)
}

/// Every file the source's message-file values name, when there is an `EventMessageFile` and every value
/// was read in full and names absolute paths only; `None` otherwise.
fn message_files(ctx: &ScanCtx<'_>, key: &str, values: &[RegValue]) -> Option<Vec<String>> {
    let mut files: Vec<String> = Vec::new();
    let mut event_files = 0usize;
    for value_name in MESSAGE_FILE_VALUES {
        let Some(value) = values.iter().find(|v| prefix::eq_ci(&v.name, value_name)) else {
            continue;
        };
        // A message-file value not read in full says nothing about which files it names.
        if !value.data.is_complete() || value.data.has_text_after_nul() {
            ctx.ext.warn(
                ID,
                format!(
                    "{key}\\{}: not read in full; the source is not offered",
                    value.name
                ),
            );
            return None;
        }
        // A message-file value that is no string is no registration this scanner understands.
        let text = value.data.string()?;
        for entry in text.split(';') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let file = message_file(ctx, entry)?;
            if value_name == MESSAGE_FILE_VALUES[0] {
                event_files += 1;
            }
            if !files.iter().any(|f| prefix::is_same(f, &file)) {
                files.push(file);
            }
        }
    }
    (event_files > 0).then_some(files)
}

/// The candidate for the source `name` of the log key `log_key`, or nothing.
fn source_candidate(
    ctx: &ScanCtx<'_>,
    log_key: &str,
    name: &str,
    msi_rows: &[(String, String)],
) -> Option<Candidate> {
    let key = format!(r"{log_key}\{name}");
    // A source whose values cannot be read (access denied, not captured) is not offered.
    let values = ctx
        .reg
        .values(&key)
        .map_err(|e| warn_unread(ctx, ID, &key, &e))
        .ok()?;
    let files = message_files(ctx, &key, &values)?;
    // Every message file must be the app's: a Windows or .NET message file makes the source not the
    // app's, whatever it is called.
    let own = |file: &str| ctx.inside_install_root(file).is_some() || ctx.is_app_file(file);
    if !files.iter().all(|f| own(f)) {
        return None;
    }
    let target = Target::RegKey { path: key };
    if ctx.in_baseline(&target) {
        return None;
    }
    let all_missing = files.iter().all(|f| ctx.fs.exists(f).is_absent());

    let mut b = ctx.candidate(ID, target, Action::DeleteKey, Category::Registration);
    for (product, row) in msi_rows {
        b = b.msi_row(product, "Registry", row);
    }
    let declared = b
        .evidence()
        .iter()
        .any(|e| e.kind == EvidenceKind::InstallerManifest(ManifestKind::Msi));
    b.chained_ref(Tier::A, &files[0]);
    if !declared {
        b.cap_at_tier_b("no installer record of this event source");
    } else if !all_missing {
        b.cap_at_tier_b("a message file of this event source is still there");
    }
    for file in &files {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_are_well_formed() {
        assert!(ROOTS.iter().all(RootSpec::is_well_formed));
    }

    #[test]
    fn tracing_stems_are_whole_names_before_a_suffix() {
        assert_eq!(tracing_stem("7zFM_RASAPI32"), Some("7zFM"));
        assert_eq!(tracing_stem("app_rasmancs"), Some("app"));
        assert_eq!(tracing_stem("my_app_RASAPI32"), Some("my_app"));
        assert_eq!(tracing_stem("_RASAPI32"), None);
        assert_eq!(tracing_stem("app_RASAPI"), None);
        assert_eq!(tracing_stem("app"), None);
    }

    #[test]
    fn generic_stems() {
        for stem in [
            "setup", "Setup", "update", "helper", "launcher", "unins000", "UNINS001",
        ] {
            assert!(generic_stem(stem), "{stem}");
        }
        for stem in ["7zFM", "myapp", "unins", "uninsx", "setupapp"] {
            assert!(!generic_stem(stem), "{stem}");
        }
    }
}
