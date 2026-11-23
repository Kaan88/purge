//! `quarantine.expiring` and `quarantine.purge` through the purge dialog (M3 design 6.3, 8.2, package
//! M3-PURGE).
//!
//! # What the client can say
//!
//! `quarantine.expiring` takes one flag, `include_not_due`: whether the answer also lists the
//! quarantined items whose retention has not ended (each marked `due: false`), for the vault's
//! "Delete now". `quarantine.purge` takes a list of [`ExpiryId`]s and nothing
//! else: no path, no item, no user-data flag, and no word about whether an entry is due. The ids are
//! not stored in a table: each one is a stable
//! hash of the executor's own `<session>/<op>` id ([`purge_exec::expiry::ExpiryId`]), and every id a
//! request names is looked up in a **fresh** listing of the broker's own store at purge time. An id
//! that is not in that listing is `gone` (`expiry`) before any dialog opens; a duplicate id is used
//! once. Taking an id from the client therefore selects a unit the broker itself listed, never a path
//! or a category the client supplied.
//!
//! The listing is recomputed rather than cached, so an item restored (or finished by an earlier
//! purge) between the vault's `quarantine.expiring` and its `quarantine.purge` is no longer due and
//! its id is `gone`: a purge cannot be replayed, and a second `quarantine.purge` of the same ids
//! purges nothing.
//!
//! # What the user sees
//!
//! The units the request named are split with [`purge_exec::expiry::ExpiryListing`]'s own user-data
//! flag (`consent::view::split_purge`): the items that are not user data are named in one dialog
//! ([`view::view_purge`]), and **every user-data item gets a dialog of its own**
//! ([`view::view_purge_user_data`]). `view_purge` itself refuses a user-data unit
//! (`ViewError::UserDataMisplaced`), so a missed split fails closed. Cancelling the bulk dialog
//! answers `consent_declined` and nothing is purged; cancelling one user-data dialog keeps that item
//! and leaves the other decisions standing. When every dialog of the request is declined the answer is
//! `consent_declined`, not `partial`, and the broker does not end on it (review S3).
//!
//! # Delete now: a quarantined item before its retention ends
//!
//! The retention is how long Purge keeps an item unasked, not a lock on the user (DECISIONS
//! 2026-11-23). An id of the fresh listing that names a quarantined item whose retention has **not**
//! ended is therefore not `gone`: it is asked for in dialogs of its own kind, after those of the
//! expired units. The broker reads "not due" from its own listing at purge time; the request cannot
//! say it, and cannot hide it. The items that are not user data are named in one dialog
//! ([`view::view_delete_now`]) and every user-data item in a dialog of its own
//! ([`view::view_delete_now_user_data`]); each says that this is before the retention date, that it
//! cannot be undone, and that Undo and History can no longer restore the items. Cancelling the
//! "Delete now" bulk dialog keeps every not-due item of the request (no user-data dialog of them is
//! asked) and leaves the decisions about expired units standing.
//!
//! That dialog is for quarantined items only: `view_delete_now` refuses a backup unit, and the early
//! mark it gives ([`PurgeConsent::allow_early`]) deletes no backup file in the executor.
//!
//! # Backups before their retention ends (DECISIONS 2026-11-24)
//!
//! `quarantine.expiring {include_backups_not_due}` also lists, per op, the backups (registry backups
//! and definitions) whose class is not due and that nothing holds. An id of the fresh listing that
//! names such a backup is asked for **last, in a dialog kind of its own**
//! ([`view::view_delete_backups_now`], user data one backup per dialog): it names each backup with the
//! change it would undo and every file, says that Undo can then no longer restore those registry
//! changes, and has its own confirmation code. Only its approval sets
//! [`PurgeConsent::allow_early_backup`]; the "Delete now" approval of the files never does. Cancel
//! keeps every such backup. When the request named files that are not due and none of their "Delete
//! now" dialogs was approved (the bulk dialog cancelled, or every user-data dialog of a request that
//! had only those), the backup dialog is not asked at all: whoever kept every file is not asked to
//! give up the registry undo. The request itself still says nothing but ids; a client's checkbox is
//! a request, never the consent.
//!
//! # After a move: `plan.execute {delete_after}`
//!
//! [`Purger::delete_after_run`] is the second step of "delete instead of keeping in quarantine": it
//! takes no id from the client at all. It lists the store afresh, takes the quarantined items of the
//! session the run just made (never a backup, never another session), and asks for them in the same
//! "Delete now" dialogs as above. Declined, lost, busy or failed: the items stay in quarantine.
//!
//! # The consent
//!
//! [`PurgeConsent`] is then built from **only** the units whose dialog was approved: the ids are
//! named, user-data units are confirmed one by one, every backup file of an approved backup unit
//! is named by its session-relative path, an item approved in a "Delete now" dialog is allowed
//! early ([`PurgeConsent::allow_early`]) and a backup approved in the dialog that deletes backups
//! early likewise ([`PurgeConsent::allow_early_backup`]), which is what the executor's `expire`
//! record then says.
//! `purge_exec::expiry::purge` refuses the whole request if the
//! consent misses an id, so the dialog is the only gate to a deletion.
//!
//! # Ending
//!
//! `quarantine.purge` is a completed change of the broker (design 3.6): a successful one ends the
//! broker once the client closes and no session is open. If the client or its parent is lost, a dialog
//! open at that moment closes as Cancel (the core's [`crate::lifetime::Closer`]) and nothing is
//! purged; a purge whose dialog was already approved runs to the end even when the answer can no
//! longer be sent.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use purge_exec::expiry::{
    self, ExpiringBackup, ExpiringItem, ExpiryId as ExecExpiryId, PurgeConsent, PurgeError,
    PurgeOutcome, PurgeReport,
};
use purge_exec::plan_in::selection_hash;
use purge_exec::storage::{StorageError, StorageRoots};
use purge_model::exec::session::{RetentionClass, SessionId};
use purge_model::{CandidateId, FileTime};
use purge_rpc::error::{ErrorData, ErrorObject, IdKind};
use purge_rpc::methods::{
    DeleteAfter, DeleteAfterOutcome, ExpiringItem as WireItem, ExpiringList, ExpiringParams,
    ExpiryId, PipeCall, PurgeParams, PurgeResult,
};
use purge_win::taskdialog::Outcome;
use serde_json::Value;

use crate::consent::dialog;
use crate::consent::view::{self, PurgeUnit};
use crate::serve::{Ctx, Handler};
use crate::session::gone;

/// Ticks between the Windows epoch (1601) and the Unix epoch (1970).
const UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;

/// The current time as a FILETIME. The executor judges retention on this value and records it in its
/// expire records.
pub(crate) fn system_now() -> FileTime {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() / 100);
    FileTime(UNIX_EPOCH_TICKS.saturating_add(u64::try_from(since).unwrap_or(u64::MAX)))
}

/// What an expiry listing of the store holds, as far as the purge handler needs it.
#[derive(Debug, Clone, Default)]
pub struct Listing {
    /// Quarantined items that are due.
    pub items: Vec<ExpiringItem>,
    /// Backup files of one op that are due.
    pub backups: Vec<ExpiringBackup>,
    /// Quarantined items whose retention has not ended and that nothing holds: deleted only through a
    /// "Delete now" dialog.
    pub not_due: Vec<ExpiringItem>,
    /// Backup files of one op whose class is not due and that nothing holds: deleted only through
    /// the dialog that deletes backups early.
    pub not_due_backups: Vec<ExpiringBackup>,
    /// The app of each session, for display; a session without an index entry is absent and its
    /// items carry an empty app.
    pub apps: BTreeMap<SessionId, String>,
}

/// The store the purge handler reads and changes. The real implementation is [`StorageExpiry`]; the
/// tests script it.
pub trait ExpirySource: Send + Sync + 'static {
    /// The time retention is judged at and expire records carry.
    fn now(&self) -> FileTime;

    /// Lists what is due at `now`. Changes nothing.
    fn listing(&self, now: FileTime) -> Result<Listing, StorageError>;

    /// Whether another operation writes the store now (another broker's run, undo, recovery or purge):
    /// asked before the first dialog, so the user is not asked to delete what the purge's own lock
    /// would refuse. Only a hint; [`ExpirySource::purge`] takes the lock. The tests' sources have no
    /// other writer unless they say so.
    fn writer_busy(&self) -> bool {
        false
    }

    /// Permanently deletes `ids`, gated by `consent` (see [`ExpirySource::listing`] and
    /// [`purge_exec::expiry::purge`]). `ids` are distinct and are the broker's own units.
    fn purge(
        &self,
        ids: &[ExecExpiryId],
        consent: &PurgeConsent,
        now: FileTime,
    ) -> Result<PurgeReport, PurgeError>;
}

/// The real store: the checked [`StorageRoots`] the broker started with.
#[derive(Debug, Clone)]
pub struct StorageExpiry {
    roots: StorageRoots,
}

impl StorageExpiry {
    /// Storage over the roots the start checks produced.
    pub fn new(roots: StorageRoots) -> StorageExpiry {
        StorageExpiry { roots }
    }
}

impl ExpirySource for StorageExpiry {
    fn now(&self) -> FileTime {
        system_now()
    }

    fn listing(&self, now: FileTime) -> Result<Listing, StorageError> {
        let listing = expiry::expiring(&self.roots, now)?;
        // The index is for display only: a session whose entry cannot be read still lists its items,
        // with an empty app. The executor has already read the journal, not the index, for the due
        // marks.
        let apps = self
            .roots
            .read_index()
            .map(|index| {
                index
                    .sessions
                    .into_iter()
                    .map(|summary| (summary.id, summary.app))
                    .collect()
            })
            .unwrap_or_default();
        Ok(Listing {
            items: listing.items,
            backups: listing.backups,
            not_due: listing.not_due,
            not_due_backups: listing.not_due_backups,
            apps,
        })
    }

    fn writer_busy(&self) -> bool {
        // A lock file the store refuses is not a busy writer: the purge's own lock reports it.
        self.roots.writer_busy().unwrap_or(false)
    }

    fn purge(
        &self,
        ids: &[ExecExpiryId],
        consent: &PurgeConsent,
        now: FileTime,
    ) -> Result<PurgeReport, PurgeError> {
        expiry::purge(&self.roots, ids, consent, now)
    }
}

/// The handler of `quarantine.expiring` and `quarantine.purge`, over one source.
#[derive(Clone)]
pub struct Purger {
    source: Arc<dyn ExpirySource>,
}

impl Purger {
    /// A handler over `source`.
    pub fn new(source: Arc<dyn ExpirySource>) -> Purger {
        Purger { source }
    }

    /// A handler over the checked store the broker started with.
    pub fn from_store(roots: StorageRoots) -> Purger {
        Purger::new(Arc::new(StorageExpiry::new(roots)))
    }

    /// Runs one request when it is one of this handler's, and answers `None` for every other. The
    /// dispatcher calls it before its own methods.
    pub fn handle<H: Handler>(
        &self,
        ctx: &Ctx<'_, H>,
        call: &PipeCall,
    ) -> Option<Result<Value, ErrorObject>> {
        match call {
            PipeCall::QuarantineExpiring(params) => Some(self.expiring(*params).and_then(|list| {
                serde_json::to_value(list).map_err(|e| ErrorObject::runtime(e.to_string()))
            })),
            PipeCall::QuarantinePurge(params) => Some(self.purge(ctx, params).and_then(|result| {
                serde_json::to_value(result).map_err(|e| ErrorObject::runtime(e.to_string()))
            })),
            _ => None,
        }
    }

    /// `quarantine.expiring`: the units that are due, each with the id a purge request can name; with
    /// `include_not_due`, after them the quarantined items whose retention has not ended; with
    /// `include_backups_not_due`, last, the backups whose retention has not ended.
    pub fn expiring(&self, params: ExpiringParams) -> Result<ExpiringList, ErrorObject> {
        let now = self.source.now();
        let listing = self.source.listing(now).map_err(store_error)?;
        // Two units with one id would make the purge ambiguous; refuse the listing instead.
        id_map(&listing)?;
        let mut items = Vec::with_capacity(listing.items.len() + listing.backups.len());
        let quarantined = |item: &ExpiringItem, due: bool| WireItem {
            expiry_id: wire_id(&item.id),
            session: item.id.session.clone(),
            app: listing
                .apps
                .get(&item.id.session)
                .cloned()
                .unwrap_or_default(),
            class: RetentionClass::Quarantine,
            expired: item.expires,
            due,
            files: vec![item.original_path.clone()],
            bytes: item.bytes,
            user_data: item.user_data,
        };
        let backed_up = |backup: &ExpiringBackup, due: bool| WireItem {
            expiry_id: wire_id(&backup.id),
            session: backup.id.session.clone(),
            app: listing
                .apps
                .get(&backup.id.session)
                .cloned()
                .unwrap_or_default(),
            class: RetentionClass::Backup,
            expired: backup.expires,
            due,
            files: backup.files.clone(),
            bytes: backup.bytes,
            user_data: backup.user_data,
        };
        for item in &listing.items {
            items.push(quarantined(item, true));
        }
        for backup in &listing.backups {
            items.push(backed_up(backup, true));
        }
        if params.include_not_due {
            for item in &listing.not_due {
                items.push(quarantined(item, false));
            }
        }
        if params.include_backups_not_due {
            for backup in &listing.not_due_backups {
                items.push(backed_up(backup, false));
            }
        }
        Ok(ExpiringList { items })
    }

    /// `quarantine.purge`: names what the request's ids denote in a fresh listing, asks the dialogs,
    /// and deletes only the units those dialogs approved.
    pub fn purge<H: Handler>(
        &self,
        ctx: &Ctx<'_, H>,
        params: &PurgeParams,
    ) -> Result<PurgeResult, ErrorObject> {
        let now = self.source.now();
        let listing = self.source.listing(now).map_err(store_error)?;
        let map = id_map(&listing)?;

        // Every id must name a unit of the listing made now (due, or a quarantined item that is not
        // due yet), and it is used once. An unknown or already purged id refuses the whole request
        // before a dialog opens (nothing was shown, nothing is changed).
        let mut requested: BTreeSet<ExecExpiryId> = BTreeSet::new();
        for id in params.expiry_ids.as_slice() {
            let unit = map.get(id).ok_or_else(|| gone(IdKind::Expiry))?;
            requested.insert(unit.clone());
        }
        self.ask_and_purge(ctx, &listing, &requested, now)
    }

    /// The second step of `plan.execute {delete_after}` ("delete instead of keeping in quarantine"):
    /// asks, in the "Delete now" dialogs, for the quarantined items of `session` (the session the run
    /// just made) and deletes those approved. No id comes from the client: the items are the ones a
    /// listing made now holds for that session, and only quarantined items (no backup, nothing of
    /// another session, nothing that is held). Never an error: whatever goes wrong, the items the
    /// answer does not count as purged are still in quarantine.
    pub fn delete_after_run<H: Handler>(
        &self,
        ctx: &Ctx<'_, H>,
        session: &SessionId,
    ) -> DeleteAfter {
        let answer = |outcome, purged: usize, kept: usize| DeleteAfter {
            outcome,
            purged: u32::try_from(purged).unwrap_or(u32::MAX),
            kept: u32::try_from(kept).unwrap_or(u32::MAX),
        };
        let now = self.source.now();
        let Ok(listing) = self.source.listing(now) else {
            return answer(DeleteAfterOutcome::Failed, 0, 0);
        };
        let moved: Vec<ExpiringItem> = listing
            .not_due
            .into_iter()
            .filter(|item| item.id.session == *session)
            .collect();
        if moved.is_empty() {
            return answer(DeleteAfterOutcome::Nothing, 0, 0);
        }
        let requested: BTreeSet<ExecExpiryId> = moved.iter().map(|item| item.id.clone()).collect();
        // The listing the dialogs are drawn from holds these items and nothing else.
        let only = Listing {
            not_due: moved,
            apps: listing.apps,
            ..Listing::default()
        };
        match self.ask_and_purge(ctx, &only, &requested, now) {
            Ok(result) if result.kept == 0 => {
                answer(DeleteAfterOutcome::Deleted, requested.len(), 0)
            }
            Ok(result) => answer(
                if result.purged == 0 {
                    DeleteAfterOutcome::Failed
                } else {
                    DeleteAfterOutcome::Partial
                },
                result.purged as usize,
                result.kept as usize,
            ),
            Err(e) if matches!(e.data, Some(ErrorData::ConsentDeclined)) => {
                answer(DeleteAfterOutcome::Declined, 0, requested.len())
            }
            Err(_) => answer(DeleteAfterOutcome::Failed, 0, requested.len()),
        }
    }

    /// Asks for the units `requested` of `listing` in the dialogs of their kinds and deletes only
    /// what those dialogs approved.
    fn ask_and_purge<H: Handler>(
        &self,
        ctx: &Ctx<'_, H>,
        listing: &Listing,
        requested: &BTreeSet<ExecExpiryId>,
        now: FileTime,
    ) -> Result<PurgeResult, ErrorObject> {
        // Only the requested units: a due item the request did not name is never offered and never
        // purged.
        let items: Vec<ExpiringItem> = listing
            .items
            .iter()
            .filter(|item| requested.contains(&item.id))
            .cloned()
            .collect();
        let backups: Vec<ExpiringBackup> = listing
            .backups
            .iter()
            .filter(|backup| requested.contains(&backup.id))
            .cloned()
            .collect();
        // The requested items whose retention has not ended, by the listing made now and nothing
        // else: these are a "Delete now" and get the dialogs that say so.
        let not_due: Vec<ExpiringItem> = listing
            .not_due
            .iter()
            .filter(|item| requested.contains(&item.id))
            .cloned()
            .collect();
        // The requested backups whose class is not due, likewise by the listing made now: these get
        // the dialog that says the registry changes can then no longer be undone.
        let not_due_backups: Vec<ExpiringBackup> = listing
            .not_due_backups
            .iter()
            .filter(|backup| requested.contains(&backup.id))
            .cloned()
            .collect();

        // The executor's own user-data flag decides the dialog, never the client. `view_purge`
        // refuses a user-data unit, so a split that missed one fails closed.
        let (bulk, personal) = view::split_purge(&items, &backups);
        let (now_bulk, now_personal) = view::split_purge(&not_due, &[]);
        let (backups_bulk, backups_personal) = view::split_purge(&[], &not_due_backups);
        // No dialog while another broker writes the store: the purge would be refused after it.
        if self.source.writer_busy() {
            return Err(ErrorObject::server(ErrorData::Busy));
        }
        let mut named: Vec<ExecExpiryId> = Vec::new();
        let mut confirmed: Vec<ExecExpiryId> = Vec::new();
        let mut files: Vec<(ExecExpiryId, Vec<String>)> = Vec::new();
        // The items approved in a "Delete now" dialog; only these are allowed before their retention
        // ends.
        let mut early: Vec<ExecExpiryId> = Vec::new();
        // The backups approved in the dialog that deletes backups early; only these, and by no
        // other dialog's approval.
        let mut early_backups: Vec<ExecExpiryId> = Vec::new();

        if !bulk.is_empty() {
            let Ok(page_view) = view::view_purge(&bulk) else {
                return Err(consent_declined());
            };
            if dialog::ask(ctx, &page_view) != Outcome::Approved {
                // The bulk dialog is the request's own consent: Cancel stops here, before any
                // user-data dialog, and changes nothing.
                return Err(consent_declined());
            }
            for unit in &bulk {
                named.push(unit.id().clone());
                if let PurgeUnit::Backup(backup) = unit {
                    files.push((backup.id.clone(), backup.files.clone()));
                }
            }
        }

        for unit in personal {
            let Ok(page_view) = view::view_purge_user_data(unit) else {
                // A name that cannot be shown fails safe: that item stays.
                continue;
            };
            if dialog::ask(ctx, &page_view) == Outcome::Approved {
                named.push(unit.id().clone());
                confirmed.push(unit.id().clone());
                if let PurgeUnit::Backup(backup) = unit {
                    files.push((backup.id.clone(), backup.files.clone()));
                }
            } else if ctx.lost() {
                // Every other dialog would be declined without asking; stop.
                break;
            }
        }

        // Delete now: the items whose retention has not ended, in dialogs that say so. A view that
        // cannot be built (a backup, a user-data unit in the bulk) fails safe: those items stay.
        let now_approved = now_bulk.is_empty()
            || view::view_delete_now(&now_bulk).is_ok_and(|page_view| {
                !ctx.lost() && dialog::ask(ctx, &page_view) == Outcome::Approved
            });
        if now_approved {
            for unit in &now_bulk {
                named.push(unit.id().clone());
                early.push(unit.id().clone());
            }
            for unit in now_personal {
                if ctx.lost() {
                    break;
                }
                let Ok(page_view) = view::view_delete_now_user_data(unit) else {
                    continue;
                };
                if dialog::ask(ctx, &page_view) == Outcome::Approved {
                    named.push(unit.id().clone());
                    confirmed.push(unit.id().clone());
                    early.push(unit.id().clone());
                }
            }
        }

        // Backups before their retention ends, last and in a dialog kind of their own. Not asked at
        // all when the request named files that are not due and none of their "Delete now" dialogs
        // was approved (the bulk one cancelled, or, for a request of user data only, every one of
        // them): a user who kept every file is not then asked to give up the registry undo. A view
        // that cannot be built fails safe: those backups stay.
        let files_declined = !not_due.is_empty() && early.is_empty();
        let backups_approved = !files_declined
            && (backups_bulk.is_empty()
                || view::view_delete_backups_now(&backups_bulk).is_ok_and(|page_view| {
                    !ctx.lost() && dialog::ask(ctx, &page_view) == Outcome::Approved
                }));
        if backups_approved {
            let mut approve = |unit: &PurgeUnit<'_>| {
                if let PurgeUnit::Backup(backup) = unit {
                    named.push(backup.id.clone());
                    early_backups.push(backup.id.clone());
                    files.push((backup.id.clone(), backup.files.clone()));
                }
            };
            for unit in &backups_bulk {
                approve(unit);
            }
            for unit in backups_personal {
                if ctx.lost() {
                    break;
                }
                let Ok(page_view) = view::view_delete_backups_now_user_data(unit) else {
                    continue;
                };
                if dialog::ask(ctx, &page_view) == Outcome::Approved {
                    approve(&unit);
                    confirmed.push(unit.id().clone());
                }
            }
        }

        // No dialog of this request was approved: the request is declined, not a partial purge. The
        // broker must not count it as a completed change and must not end (review S3).
        if named.is_empty() {
            return Err(consent_declined());
        }

        let mut consent = PurgeConsent::naming(named.iter().cloned());
        for id in &confirmed {
            consent.confirm_user_data(id.clone());
        }
        for id in &early {
            consent.allow_early(id.clone());
        }
        for id in &early_backups {
            consent.allow_early_backup(id.clone());
        }
        for (id, names) in files {
            consent.name_files(id, names);
        }

        // `named` is the set of units whose dialogs were approved; the executor refuses the whole
        // request if the consent does not name one of them, which would be a bug here.
        let report = self
            .source
            .purge(&named, &consent, now)
            .map_err(|e| match e {
                PurgeError::NotConsented(missing) => ErrorObject::runtime(format!(
                    "internal error: {} approved purge unit(s) were not named in the consent",
                    missing.len()
                )),
                PurgeError::Store(e) => store_error(e),
            })?;

        let gone: Vec<&ExecExpiryId> = report
            .items
            .iter()
            .filter(|result| {
                matches!(
                    result.outcome,
                    PurgeOutcome::Purged | PurgeOutcome::AlreadyGone
                )
            })
            .map(|result| &result.id)
            .collect();
        let purged = gone.len();
        let purged_backups = gone
            .iter()
            .filter(|id| {
                backups
                    .iter()
                    .chain(&not_due_backups)
                    .any(|backup| backup.id == ***id)
            })
            .count();
        let kept = requested.len().saturating_sub(purged);
        Ok(PurgeResult {
            outcome: if kept == 0 {
                purge_rpc::error::Outcome::Complete
            } else {
                purge_rpc::error::Outcome::Partial
            },
            purged: u32::try_from(purged).unwrap_or(u32::MAX),
            kept: u32::try_from(kept).unwrap_or(u32::MAX),
            purged_backups: u32::try_from(purged_backups).unwrap_or(u32::MAX),
        })
    }
}

/// The broker id of an executor unit: a stable 64-bit hash of `<session>/<op>`. The id form of
/// [`ExpiryId`] is fixed (`e-<16 hex>`), so a path cannot read as one, and the value carries nothing
/// the client can change.
fn wire_id(id: &ExecExpiryId) -> ExpiryId {
    let text = CandidateId(id.to_string());
    let hash = selection_hash(std::iter::once(&text));
    let b = hash.as_bytes();
    ExpiryId::from_bits(u64::from_be_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// Every unit of `listing` by its broker id. Two units with one id are refused: a purge by id must
/// name exactly one unit.
fn id_map(listing: &Listing) -> Result<BTreeMap<ExpiryId, ExecExpiryId>, ErrorObject> {
    let mut map = BTreeMap::new();
    for id in listing
        .items
        .iter()
        .map(|item| &item.id)
        .chain(listing.backups.iter().map(|backup| &backup.id))
        .chain(listing.not_due.iter().map(|item| &item.id))
        .chain(listing.not_due_backups.iter().map(|backup| &backup.id))
    {
        if map.insert(wire_id(id), id.clone()).is_some() {
            return Err(ErrorObject::runtime(
                "two expired entries share one broker id; nothing is offered",
            ));
        }
    }
    Ok(map)
}

/// A store error as the RPC names it: the store's own check is `store_integrity`, another writer of
/// the store (another broker's run, undo, recovery or purge) is `busy`, anything else `runtime` (the
/// design's 6.4 kinds, mirroring the CLI's `storage_exit`).
fn store_error(e: StorageError) -> ErrorObject {
    match e {
        StorageError::WriterBusy { .. } => ErrorObject::server(ErrorData::Busy),
        e @ (StorageError::Integrity { .. }
        | StorageError::VolumeRoot { .. }
        | StorageError::VolumeMismatch { .. }) => ErrorObject::server(ErrorData::StoreIntegrity {
            message: e.to_string(),
        }),
        e => ErrorObject::runtime(e.to_string()),
    }
}

/// The one error of a Cancel in a dialog; nothing was changed.
fn consent_declined() -> ErrorObject {
    ErrorObject::server(ErrorData::ConsentDeclined)
}

#[cfg(test)]
mod tests;
