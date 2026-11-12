//! CLS-ASSOC (ENGINE_PLAN.md §5.6): `.ext` keys: `OpenWithProgids` values, `OpenWithList\<exe>`,
//! `SystemFileAssociations`, defaults and skeletons (§5.7.1).
//!
//! The scanner walks the fingerprint's extension journal; an extension the harvest did not journal is
//! not looked at. For each entry, in this order:
//!
//! 1. **Values.** Every `OpenWithProgids` value named exactly by a ProgID of P is a `RegValue` candidate
//!    (`InPreUninstallRefSnapshot` and `ChainedRef`, Value scope).
//! 2. **Exe-named keys.** `OpenWithList\<exe>` below the extension and below
//!    `SystemFileAssociations\<.ext>`, for the app's main exes, and `SystemFileAssociations\<.ext>\shell`
//!    verbs whose command runs a file of the app. These have only a Key-scope `ChainedRef` and are
//!    therefore offered, never preselected.
//! 3. **Skeletons.** `OpenWithProgids`, or the whole `.ext` key, left empty by the uninstaller: a
//!    `RegKey` candidate with `ProvenOwnedSkeleton` when a baseline of exactly this (edition, build.ubr)
//!    is loaded and does not contain it. A whole-`.ext` candidate names its `OpenWithProgids` child in
//!    `children` instead of emitting it separately. Without a matching baseline the key goes out under
//!    the scanner id `X-SYSTIDY` with band-neutral evidence (§5.7.1 step 3); with a TrustedInstaller
//!    owner or ACE it carries the hard blocker.
//! 4. **Default.** A default that names a ProgID of P is offered for restoring: from the vendor's backup
//!    value, or from the baseline when the baseline has a default for the extension. The item is a
//!    `RegValue` with `action = restore` in its facts and harm Medium, so it is never preselected. With
//!    neither source it is report-only ("`<.ext>` has no default app; choose one in Settings").
//!
//! The rules themselves live in the private [`handler`] module, which CLS-FILEEXTS and CLS-TOASTS share.
//! Every candidate carries `group = "File associations"` in its evidence details.

use purge_guard::prefix;
use purge_index::queries;
use purge_model::{
    Action, AnchorKind, Candidate, CandidateId, Category, ExtJournalEntry, Facts, Harm, Target,
    Tier,
};
use purge_source::types::{REG_SZ, RegData};

use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};

pub(crate) mod handler;

use handler::{KeyState, OPEN_WITH_LIST, OPEN_WITH_PROGIDS};

/// The scanner's catalog id.
pub const ID: &str = "CLS-ASSOC";

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[RootSpec::reg(r"*\SOFTWARE\Classes", None)];

/// The CLS-ASSOC scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClsAssoc;

impl Scanner for ClsAssoc {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, app: &AppIdentityView) -> Vec<Candidate> {
        let mut out = Unique::default();
        for entry in &ctx.fp.ext_journal {
            let Some(root) = handler::classes_root(entry) else {
                continue;
            };
            let facts = Facts::new().with("ext", entry.ext.clone());
            let ext_state = handler::key_state(ctx, &entry.key);
            let owp_key = handler::subkey(&entry.key, OPEN_WITH_PROGIDS);
            let owp_state = handler::key_state(ctx, &owp_key);

            // 1. Values named exactly in P.
            for value in owp_state.values() {
                let Some(progid) = handler::progid_in_p(ctx, &value.name) else {
                    continue;
                };
                let listed = entry
                    .openwith_ours
                    .iter()
                    .any(|name| prefix::eq_ci(name, &value.name));
                out.extend(handler::progid_value(
                    ctx,
                    ID,
                    &owp_key,
                    &value.name,
                    progid,
                    listed,
                    &facts,
                ));
            }

            // 2. Keys named after the app's exes, and verbs that run them.
            let sfa = handler::subkey(&handler::subkey(root, "SystemFileAssociations"), &entry.ext);
            for list_key in [&entry.key, &sfa] {
                let list_key = handler::subkey(list_key, OPEN_WITH_LIST);
                out.extend(handler::exe_named_subkeys(ctx, ID, &list_key, &facts));
            }
            out.extend(verbs(ctx, app, &handler::subkey(&sfa, "shell"), &facts));

            // 3. Skeleton keys.
            if let Some(skeleton) = handler::skeleton(ctx, entry, &ext_state, &owp_state) {
                out.extend(handler::skeleton_candidate(
                    ctx, ID, entry, &skeleton, &facts,
                ));
            }

            // 4. A default that names a ProgID of P.
            out.extend(default_candidate(ctx, entry, &ext_state, &facts));
        }
        out.items
    }
}

/// Candidates in emission order, one per target.
#[derive(Default)]
struct Unique {
    items: Vec<Candidate>,
    seen: Vec<CandidateId>,
}

impl Unique {
    fn extend(&mut self, candidates: impl IntoIterator<Item = Candidate>) {
        for candidate in candidates {
            if !self.seen.contains(&candidate.id) {
                self.seen.push(candidate.id.clone());
                self.items.push(candidate);
            }
        }
    }
}

/// `SystemFileAssociations\<.ext>\shell\<verb>` keys whose command names a file under an InstallRoot or
/// of the exe set by its full path. A bare exe name is not enough.
fn verbs(
    ctx: &ScanCtx<'_>,
    app: &AppIdentityView,
    shell_key: &str,
    facts: &Facts,
) -> Vec<Candidate> {
    let mut out = Vec::new();
    for verb in handler::key_state(ctx, shell_key).subkeys() {
        let verb_key = handler::subkey(shell_key, verb);
        let command_key = handler::subkey(&verb_key, "command");
        let command_state = handler::key_state(ctx, &command_key);
        let Some(command) = command_state
            .values()
            .iter()
            .find(|v| v.name.is_empty())
            .and_then(handler::complete_string)
        else {
            continue;
        };
        let Some(path) = app
            .refs
            .find_all(&command)
            .into_iter()
            .filter(|m| !m.name_only && matches!(m.anchor.kind, AnchorKind::Root | AnchorKind::Exe))
            .filter_map(|m| m.path)
            .find(|path| ctx.inside_install_root(path).is_some() || ctx.is_app_file(path))
        else {
            continue;
        };
        let target = Target::RegKey { path: verb_key };
        let mut builder = ctx.candidate(ID, target, Action::DeleteKey, Category::Association);
        builder.chained_ref(Tier::A, &path);
        builder.common_blockers();
        out.extend(handler::finish(
            builder,
            None,
            &facts.clone().with("path", path),
        ));
    }
    out
}

/// Where the previous default of an extension can be restored from.
enum Restore {
    /// The vendor's backup value.
    VendorBackup {
        /// The backup value's name.
        value: String,
        /// The previous default.
        data: String,
    },
    /// The baseline has a default for the extension. It records a hash, not the data; the data is known
    /// only when the journal's previous default hashes to it.
    Baseline {
        /// The baseline's name.
        baseline: String,
        /// The hash of the baseline's default, as 16 hex digits.
        hash: String,
        /// The previous default, when the journal's hashes to `hash`.
        data: Option<String>,
    },
}

/// The restore source for `entry`'s default: the vendor backup first, then the baseline.
fn restore_source(ctx: &ScanCtx<'_>, entry: &ExtJournalEntry) -> Option<Restore> {
    // A backup that names one of the app's own ProgIDs would restore nothing.
    let usable =
        |data: &str| !data.trim().is_empty() && handler::progid_in_p(ctx, data.trim()).is_none();
    if let Some(backup) = entry.vendor_backup.as_ref().filter(|b| usable(&b.data)) {
        return Some(Restore::VendorBackup {
            value: backup.name.clone(),
            data: backup.data.trim().to_owned(),
        });
    }
    let (baseline, name) = handler::matching_baseline(ctx)?;
    let value = baseline.value(&entry.key, "")?;
    let data = entry
        .previous_default
        .as_deref()
        .filter(|previous| usable(previous))
        .filter(|previous| {
            value.ty == REG_SZ
                && queries::data_hash(&RegData::from_sz(previous)) == Some(value.data_hash)
        })
        .map(str::to_owned);
    Some(Restore::Baseline {
        baseline: name,
        hash: queries::hash_hex(value.data_hash),
        data,
    })
}

/// The candidate for an extension whose default names a ProgID of P (§5.7.1 step 2, fourth bullet).
///
/// The target is the default value. With a restore source the action is `DeleteValue` (the action that
/// fits a value target; the facts say `action = restore` and where from) with harm Medium, so the item is
/// offered and never preselected. Without one it is `ReportOnly`.
///
/// The `WindowsBaseline` and `ExistedBeforeInstall` blockers are deliberately not applied: a default
/// that Windows ships, or that existed before the install, is exactly the case a restore is for. The
/// owner blockers are: a value of a TrustedInstaller key is never touched.
fn default_candidate(
    ctx: &ScanCtx<'_>,
    entry: &ExtJournalEntry,
    ext_state: &KeyState,
    facts: &Facts,
) -> Option<Candidate> {
    let default = ext_state
        .values()
        .iter()
        .find(|v| v.name.is_empty())
        .and_then(handler::complete_string)?;
    let progid = handler::progid_in_p(ctx, &default)?;
    let restore = restore_source(ctx, entry);
    let target = Target::RegValue {
        path: entry.key.clone(),
        name: String::new(),
    };
    let action = if restore.is_some() {
        Action::DeleteValue
    } else {
        Action::ReportOnly
    };
    let mut builder = ctx.candidate(ID, target, action, Category::Association);
    builder.in_ref_snapshot();
    builder.chained_ref(Tier::A, progid);
    builder.owner_blockers().other_app_blockers();
    // A ProgID another installed app claims as well is not a removed one: the default still works.
    if let Some(blocker) = ctx.other_apps.anchor_blocker(AnchorKind::ProgId, progid) {
        builder.blocker(blocker);
    }

    let mut facts = facts.clone().with("progid", progid);
    match restore {
        Some(source) => {
            builder.harm(Harm::Medium);
            facts = facts.with(handler::ACTION_KEY, handler::ACTION_RESTORE);
            match source {
                Restore::VendorBackup { value, data } => {
                    facts = facts
                        .with("restore_from", "vendor_backup")
                        .with("backup_value", value)
                        .with("restore_to", data);
                }
                Restore::Baseline {
                    baseline,
                    hash,
                    data,
                } => {
                    facts = facts
                        .with("restore_from", "baseline")
                        .with("baseline", baseline)
                        .with("restore_hash", hash);
                    if let Some(data) = data {
                        facts = facts.with("restore_to", data);
                    }
                }
            }
        }
        None => {
            facts = facts
                .with(handler::ACTION_KEY, handler::ACTION_REPORT)
                .with(
                    "note",
                    format!("{} has no default app; choose one in Settings", entry.ext),
                );
            if let Some(previous) = &entry.previous_default {
                facts = facts.with("previous_default", previous.clone());
            }
        }
    }
    handler::finish(builder, None, &facts)
}
