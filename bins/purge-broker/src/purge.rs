//! `quarantine.expiring` and `quarantine.purge` through the purge dialog (M3 design 6.3, 8.2, package
//! M3-PURGE).
//!
//! # What the client can say
//!
//! `quarantine.expiring` takes nothing. `quarantine.purge` takes a list of [`ExpiryId`]s and nothing
//! else: no path, no item, no user-data flag. The ids are not stored in a table: each one is a stable
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
//! [`PurgeConsent`] is then built from **only** the units whose dialog was approved: the ids are
//! named, user-data units are confirmed one by one, and every backup file of an approved backup unit
//! is named by its session-relative path. `purge_exec::expiry::purge` refuses the whole request if the
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
    ExpiringItem as WireItem, ExpiringList, ExpiryId, PipeCall, PurgeParams, PurgeResult,
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
            apps,
        })
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
            PipeCall::QuarantineExpiring(_) => Some(self.expiring().and_then(|list| {
                serde_json::to_value(list).map_err(|e| ErrorObject::runtime(e.to_string()))
            })),
            PipeCall::QuarantinePurge(params) => Some(self.purge(ctx, params).and_then(|result| {
                serde_json::to_value(result).map_err(|e| ErrorObject::runtime(e.to_string()))
            })),
            _ => None,
        }
    }

    /// `quarantine.expiring`: the units that are due, each with the id a purge request can name.
    pub fn expiring(&self) -> Result<ExpiringList, ErrorObject> {
        let now = self.source.now();
        let listing = self.source.listing(now).map_err(store_error)?;
        // Two units with one id would make the purge ambiguous; refuse the listing instead.
        id_map(&listing)?;
        let mut items = Vec::with_capacity(listing.items.len() + listing.backups.len());
        for item in &listing.items {
            items.push(WireItem {
                expiry_id: wire_id(&item.id),
                session: item.id.session.clone(),
                app: listing
                    .apps
                    .get(&item.id.session)
                    .cloned()
                    .unwrap_or_default(),
                class: RetentionClass::Quarantine,
                expired: item.expires,
                files: vec![item.original_path.clone()],
                bytes: item.bytes,
                user_data: item.user_data,
            });
        }
        for backup in &listing.backups {
            items.push(WireItem {
                expiry_id: wire_id(&backup.id),
                session: backup.id.session.clone(),
                app: listing
                    .apps
                    .get(&backup.id.session)
                    .cloned()
                    .unwrap_or_default(),
                class: RetentionClass::Backup,
                expired: backup.expires,
                files: backup.files.clone(),
                bytes: backup.bytes,
                user_data: backup.user_data,
            });
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

        // Every id must name a unit that is due now, and it is used once. An unknown or already
        // purged id refuses the whole request before a dialog opens (nothing was shown, nothing is
        // changed).
        let mut requested: BTreeSet<ExecExpiryId> = BTreeSet::new();
        for id in params.expiry_ids.as_slice() {
            let unit = map.get(id).ok_or_else(|| gone(IdKind::Expiry))?;
            requested.insert(unit.clone());
        }

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

        // The executor's own user-data flag decides the dialog, never the client. `view_purge`
        // refuses a user-data unit, so a split that missed one fails closed.
        let (bulk, personal) = view::split_purge(&items, &backups);
        let mut named: Vec<ExecExpiryId> = Vec::new();
        let mut confirmed: Vec<ExecExpiryId> = Vec::new();
        let mut files: Vec<(ExecExpiryId, Vec<String>)> = Vec::new();

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

        // No dialog of this request was approved: the request is declined, not a partial purge. The
        // broker must not count it as a completed change and must not end (review S3).
        if named.is_empty() {
            return Err(consent_declined());
        }

        let mut consent = PurgeConsent::naming(named.iter().cloned());
        for id in &confirmed {
            consent.confirm_user_data(id.clone());
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
            })?;

        let purged = report
            .items
            .iter()
            .filter(|result| {
                matches!(
                    result.outcome,
                    PurgeOutcome::Purged | PurgeOutcome::AlreadyGone
                )
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
    {
        if map.insert(wire_id(id), id.clone()).is_some() {
            return Err(ErrorObject::runtime(
                "two expired entries share one broker id; nothing is offered",
            ));
        }
    }
    Ok(map)
}

/// A store error as the RPC names it: the store's own check is `store_integrity`, anything else
/// `runtime` (the design's 6.4 kinds, mirroring the CLI's `storage_exit`).
fn store_error(e: StorageError) -> ErrorObject {
    match e {
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
