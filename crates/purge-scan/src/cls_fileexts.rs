//! CLS-FILEEXTS (ENGINE_PLAN.md §5.6): the user's `Explorer\FileExts\.ext` `OpenWithProgids` and
//! `OpenWithList` values.
//!
//! For every extension of the fingerprint's journal the scanner reads the interactive user's
//! `FileExts\<.ext>` key (the one the journal names, otherwise the one of `Fingerprint::user_sid`) and
//! offers, always at value level:
//!
//! - `OpenWithProgids` values named exactly by a ProgID of P (`ChainedRef`, plus
//!   `InPreUninstallRefSnapshot` when the harvest recorded the value);
//! - `OpenWithList` values (`a`, `b`, …) whose data is the file name of one of the app's main exes, and
//!   for each of them the edit of `MRUList` that drops its letter. The letter is emitted as a
//!   `RegMultiSzSegment` of `MRUList` with its position: the order string is a list of one-letter
//!   entries. A bare exe name is a Tier B anchor, so these stay unticked unless the reference snapshot
//!   has the value. The name is resolved first: when a `Classes\Applications\<exe>` key of that name
//!   leads somewhere else (a portable copy the user registered), the entry is that program's and is not
//!   offered (`reg_apppaths::bare_name_leads_elsewhere`);
//! - `UserChoice\ProgId` naming a ProgID of P, as a report-only item. The deny-list refuses any change to
//!   `UserChoice` (`reg.userchoice`); the user picks a new default in Settings.
//!
//! The `FileExts\<.ext>` keys themselves are never offered. Every candidate carries
//! `group = "File associations"` in its evidence details (see `cls_assoc::handler`).

use purge_guard::prefix;
use purge_model::{Action, Candidate, Category, ExtJournalEntry, Facts, Target, Tier};

use crate::cls_assoc::handler::{self, OPEN_WITH_LIST, OPEN_WITH_PROGIDS};
use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};

/// The scanner's catalog id.
pub const ID: &str = "CLS-FILEEXTS";

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[RootSpec::reg(
    r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts",
    None,
)];

/// The keys the scanner reads single values from (entries of
/// `purge_guard::containers::VALUE_CONTAINERS`).
const VALUE_CONTAINERS: &[&str] =
    &[r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\*\OpenWithList"];

/// The `FileExts` key below a user hive.
const FILE_EXTS: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts";

/// Name of the value that orders the `OpenWithList` entries.
const MRU_LIST: &str = "MRUList";

/// The CLS-FILEEXTS scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClsFileExts;

impl Scanner for ClsFileExts {
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
        let mut out: Vec<Candidate> = Vec::new();
        let mut done: Vec<String> = Vec::new();
        for entry in &ctx.fp.ext_journal {
            let Some(key) = file_exts_key(ctx, entry) else {
                continue;
            };
            let folded = prefix::fold(&key);
            if done.contains(&folded) {
                continue;
            }
            done.push(folded);
            let facts = Facts::new().with("ext", entry.ext.clone());
            open_with_progids(ctx, &key, &facts, &mut out);
            open_with_list(ctx, app, &key, &facts, &mut out);
            out.extend(user_choice(ctx, &key, entry, &facts));
        }
        out
    }
}

/// The user's `FileExts\<.ext>` key for a journal entry: the one the journal recorded when it is well
/// formed, otherwise the one of the fingerprint's user.
fn file_exts_key(ctx: &ScanCtx<'_>, entry: &ExtJournalEntry) -> Option<String> {
    if !entry.ext.starts_with('.') || entry.ext.len() < 2 || entry.ext.contains(prefix::SEP) {
        return None;
    }
    if let Some(key) = &entry.file_exts_key {
        // Exactly `HKU\<SID>\<FILE_EXTS>\<.ext>`: a key that merely ends in `FileExts\<.ext>` somewhere
        // else is not the user's association store.
        let well_formed = prefix::leaf(key).is_some_and(|leaf| prefix::eq_ci(leaf, &entry.ext))
            && prefix::parent(key).is_some_and(|parent| {
                let folded = prefix::fold(parent);
                let mut segments = folded.split(prefix::SEP);
                segments.next() == Some("hku")
                    && segments.next().is_some_and(|sid| sid.starts_with("s-1-"))
                    && segments.collect::<Vec<_>>().join(r"\") == prefix::fold(FILE_EXTS)
            });
        return well_formed.then(|| key.clone());
    }
    let sid = ctx.fp.user_sid.trim();
    (!sid.is_empty()).then(|| format!(r"HKU\{sid}\{FILE_EXTS}\{}", entry.ext))
}

/// `OpenWithProgids` values named exactly in P.
fn open_with_progids(ctx: &ScanCtx<'_>, key: &str, facts: &Facts, out: &mut Vec<Candidate>) {
    let owp_key = handler::subkey(key, OPEN_WITH_PROGIDS);
    for value in handler::key_state(ctx, &owp_key).values() {
        if let Some(progid) = handler::progid_in_p(ctx, &value.name) {
            // The journal records that the key referenced P, not which value did: no journal evidence.
            out.extend(handler::progid_value(
                ctx,
                ID,
                &owp_key,
                &value.name,
                progid,
                false,
                facts,
            ));
        }
    }
}

/// `OpenWithList` entries whose data is one of the app's main exe names, with the `MRUList` edits.
fn open_with_list(
    ctx: &ScanCtx<'_>,
    app: &AppIdentityView,
    key: &str,
    facts: &Facts,
    out: &mut Vec<Candidate>,
) {
    let list_key = handler::subkey(key, OPEN_WITH_LIST);
    let state = handler::key_state(ctx, &list_key);
    let mru = state
        .values()
        .iter()
        .find(|v| prefix::eq_ci(&v.name, MRU_LIST))
        .and_then(handler::complete_string);
    for value in state.values() {
        if prefix::eq_ci(&value.name, MRU_LIST) || value.name.chars().count() != 1 {
            continue;
        }
        let Some(exe) = handler::complete_string(value)
            .as_deref()
            .and_then(|data| handler::own_exe_name(ctx, data))
        else {
            continue;
        };
        if crate::reg_apppaths::bare_name_leads_elsewhere(ctx, app, exe) {
            continue;
        }
        let facts = facts.clone().with("exe", exe);

        let target = Target::RegValue {
            path: list_key.clone(),
            name: value.name.clone(),
        };
        let mut builder = ctx.candidate(ID, target, Action::DeleteValue, Category::Association);
        builder.in_ref_snapshot();
        builder.chained_ref(Tier::B, exe);
        builder.common_blockers();
        out.extend(handler::finish(builder, None, &facts));

        // The entry's letter in the order string.
        let position = mru.as_deref().and_then(|order| {
            order
                .chars()
                .position(|c| prefix::eq_ci(&c.to_string(), &value.name))
        });
        if let Some(position) = position {
            let target = Target::RegMultiSzSegment {
                path: list_key.clone(),
                name: MRU_LIST.to_owned(),
                segment: value.name.clone(),
                index: u32::try_from(position).ok(),
            };
            let mut builder = ctx.candidate(ID, target, Action::EditSegment, Category::Association);
            builder.chained_ref(Tier::B, exe);
            builder.common_blockers();
            out.extend(handler::finish(builder, None, &facts));
        }
    }
}

/// `UserChoice\ProgId` naming a ProgID of P: report-only.
fn user_choice(
    ctx: &ScanCtx<'_>,
    key: &str,
    entry: &ExtJournalEntry,
    facts: &Facts,
) -> Option<Candidate> {
    let choice_key = handler::subkey(key, "UserChoice");
    let state = handler::key_state(ctx, &choice_key);
    let value = state
        .values()
        .iter()
        .find(|v| prefix::eq_ci(&v.name, "ProgId"))?;
    let progid = handler::complete_string(value)
        .as_deref()
        .and_then(|data| handler::progid_in_p(ctx, data))?;
    let target = Target::RegValue {
        path: choice_key,
        name: value.name.clone(),
    };
    let mut builder = ctx.candidate(ID, target, Action::ReportOnly, Category::Association);
    builder.chained_ref(Tier::A, progid);
    builder.common_blockers();
    let facts = facts
        .clone()
        .with("progid", progid)
        .with(handler::ACTION_KEY, handler::ACTION_REPORT)
        .with(
            "note",
            format!(
                "{} opens with an app that was removed; choose one in Settings",
                entry.ext
            ),
        );
    handler::finish(builder, None, &facts)
}
