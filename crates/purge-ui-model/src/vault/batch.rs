//! One cleanup, one volume and one quarantined item of the vault (`VaultBatchModel`,
//! `VaultVolumeModel`, `VaultItemModel`): plain data the page draws.

use purge_model::FileTime;
use purge_model::exec::session::{
    RetentionClass, SessionId, SessionState, SessionSummary, VolumeUsage,
};
use purge_rpc::methods::{ExpiringItem, ExpiryId, VolumeCap};

use super::text;
use crate::leftovers::format_size;
use crate::local_time::Clock;

/// Cleanups this close to the end of their file retention are called out.
pub const WARN_DAYS: i32 = 7;

/// One cleanup that still holds something (board 16), from its `history.index` entry: what is
/// held, on which volume, and how long it can still be put back.
#[derive(Debug, Clone, PartialEq)]
pub struct VaultBatch {
    /// The executor session.
    pub id: SessionId,
    /// The app's name, or its id when the index names no owner.
    pub name: String,
    /// When the cleanup ran.
    pub created: FileTime,
    /// "Today 10:15" or "15 Nov 10:15".
    pub when: String,
    /// The volume it holds data on, for display.
    pub volume: String,
    /// Bytes it holds.
    pub bytes: u64,
    /// Items moved (done or at the next restart).
    pub items: u32,
    /// Its quarantined files were deleted.
    pub files_purged: bool,
    /// Its registry backups were deleted.
    pub backups_purged: bool,
    /// Files deleted, registry backups kept: Put back undoes the registry changes only.
    pub registry_only: bool,
    /// When the files expire.
    pub file_expiry: FileTime,
    /// When the registry backups expire.
    pub backup_expiry: FileTime,
    /// Days the files can still be put back.
    pub file_days: i32,
    /// Days the registry backups are kept.
    pub backup_days: i32,
    /// Partly undone.
    pub partial: bool,
    /// Past a retention date: "Review and delete…" offers it.
    pub expired: bool,
    /// Within [`WARN_DAYS`] of the file retention's end.
    pub expiring: bool,
    /// "21 items · 1.2 MB on C:\".
    pub summary: String,
    /// The retention line.
    pub detail: String,
    /// The state in words.
    pub state: &'static str,
    /// The days the ring shows.
    pub days_left_shown: i32,
    /// The ring's fill, 0 to 100.
    pub ring_percent: f64,
    /// What it holds per volume.
    pub usage: Vec<VolumeUsage>,
}

/// The chip a cleanup shows; each has its own glyph, so the state never rests on colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VaultChip {
    /// Restorable (or registry undo only).
    Ok,
    /// Past a retention date.
    Expired,
    /// Close to the file retention's end.
    Expiring,
    /// Partly undone.
    Partial,
}

impl VaultBatch {
    /// Whether a session's entry still holds something to put back: committed or partly undone,
    /// with backup bytes, and not every class purged. The same rule as History's "Undoable".
    pub fn holds(s: &SessionSummary) -> bool {
        matches!(
            s.state,
            SessionState::Committed | SessionState::PartiallyUndone
        ) && s.backup_bytes > 0
            && !(s.purged.contains(&RetentionClass::Quarantine)
                && s.purged.contains(&RetentionClass::Backup))
    }

    /// The batch of one index entry.
    pub fn new(s: &SessionSummary, clock: &Clock) -> Self {
        let name = match &s.owner {
            Some(owner) if !owner.display_name.is_empty() => owner.display_name.clone(),
            _ => s.app.clone(),
        };
        let created = valid(s.started);
        let local = clock.local(created);
        let when = if local.day_number == clock.today().day_number {
            format!("Today {}", local.hh_mm())
        } else {
            local.d_mmm_hh_mm()
        };
        let volume = s
            .usage
            .iter()
            .find(|u| u.bytes > 0)
            .or(s.usage.first())
            .map(|u| u.root.clone())
            .unwrap_or_default();
        let items = s.counts.done + s.counts.pending_reboot;
        let files_purged = s.purged.contains(&RetentionClass::Quarantine);
        let backups_purged = s.purged.contains(&RetentionClass::Backup);
        let file_expiry = valid(s.expires.quarantine);
        let backup_expiry = valid(s.expires.backups);
        let file_days = if files_purged {
            0
        } else {
            clock.days_left(file_expiry)
        };
        let backup_days = if backups_purged {
            0
        } else {
            clock.days_left(backup_expiry)
        };
        // The files were deleted and only the registry backups are left: Put back can then undo
        // the registry changes only, and the row must not read as if the files could return.
        let registry_only = files_purged && !backups_purged;
        let partial = s.state == SessionState::PartiallyUndone;
        let expired = (!files_purged && file_days == 0) || (!backups_purged && backup_days == 0);
        let expiring = !expired && !files_purged && file_days <= WARN_DAYS;
        let on = if volume.is_empty() {
            String::new()
        } else {
            format!(" on {volume}")
        };
        let summary = format!(
            "{} · {}{on}",
            text::items(items),
            format_size(s.backup_bytes)
        );
        let mut parts = vec![if files_purged {
            "Files deleted".to_owned()
        } else if file_days > 0 {
            format!("Files restorable for {file_days} more days")
        } else {
            "Files expired · waiting for you to decide".to_owned()
        }];
        parts.push(if backups_purged {
            "registry backups deleted".to_owned()
        } else if registry_only {
            format!("its registry changes can be undone for {backup_days} more days")
        } else {
            format!("registry backups {backup_days} days")
        });
        if s.undone > 0 {
            parts.push(format!("{} put back", s.undone));
        }
        let state = if expired {
            text::EXPIRED
        } else if expiring {
            text::EXPIRING
        } else if registry_only {
            text::REGISTRY_ONLY
        } else if partial {
            text::PARTLY_RESTORED
        } else {
            text::RESTORABLE
        };
        let ring_percent = if files_purged {
            0.0
        } else {
            100.0 * f64::from(file_days) / Clock::days_between(created, file_expiry).max(1.0)
        };
        Self {
            id: s.id.clone(),
            name,
            created,
            when,
            volume,
            bytes: s.backup_bytes,
            items,
            files_purged,
            backups_purged,
            registry_only,
            file_expiry,
            backup_expiry,
            file_days,
            backup_days,
            partial,
            expired,
            expiring,
            summary,
            detail: parts.join(" · "),
            state,
            days_left_shown: if files_purged { backup_days } else { file_days },
            ring_percent,
            usage: s.usage.clone(),
        }
    }

    /// Whether "Also delete its registry backups" is offered: the cleanup still has some.
    pub fn can_delete_backups(&self) -> bool {
        !self.backups_purged
    }

    /// Whether "Delete now" has anything to ask the broker for: quarantined files, or (ticked)
    /// registry backups.
    pub fn can_delete_now(&self, also_backups: bool) -> bool {
        !self.files_purged || (also_backups && self.can_delete_backups())
    }

    /// What the "Delete now" choice says above its tick box.
    pub fn delete_now_intro(&self) -> &'static str {
        if self.files_purged {
            text::DELETE_NOW_INTRO_BACKUPS
        } else {
            text::DELETE_NOW_INTRO
        }
    }

    /// The chip.
    pub fn chip(&self) -> VaultChip {
        if self.expired {
            VaultChip::Expired
        } else if self.expiring {
            VaultChip::Expiring
        } else if self.partial {
            VaultChip::Partial
        } else {
            VaultChip::Ok
        }
    }
}

/// The C# `FromFileTime`: 0, or a time past what a `DateTimeOffset` holds, is "never" (0 here).
fn valid(t: FileTime) -> FileTime {
    if t.0 > i64::MAX as u64 {
        FileTime(0)
    } else {
        t
    }
}

/// One volume's quarantine use against its real cap (design delta 4), from `history.index`.
#[derive(Debug, Clone, PartialEq)]
pub struct VaultVolume {
    /// Its root.
    pub root: String,
    /// Bytes used.
    pub used: u64,
    /// The cap.
    pub cap: u64,
    /// Used of cap, 0 to 100.
    pub percent: f64,
    /// "1.2 MB of 10.0 GB limit".
    pub used_text: String,
    /// What is expired or expiring soon on it.
    pub note: String,
}

impl VaultVolume {
    /// The volume of `v`, with the bytes on it of cleanups that are expired or expiring.
    pub fn new(v: &VolumeCap, expiring_bytes: u64) -> Self {
        Self {
            root: v.root.clone(),
            used: v.used,
            cap: v.cap,
            percent: if v.cap > 0 {
                (100.0 * v.used as f64 / v.cap as f64).min(100.0)
            } else {
                0.0
            },
            used_text: format!("{} of {} limit", format_size(v.used), format_size(v.cap)),
            note: if expiring_bytes > 0 {
                format!("Expired or expiring soon: {}", format_size(expiring_bytes))
            } else {
                "Nothing expiring this week".into()
            },
        }
    }

    /// The bar's tooltip.
    pub fn tip(&self) -> String {
        format!(
            "{} {} % of its quarantine limit",
            self.root,
            self.percent.round_ties_even()
        )
    }
}

/// One quarantined item of a cleanup as the broker lists it (`quarantine.expiring
/// {include_not_due}`): the id a delete names, where the item was, its size, and whether its
/// retention has ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultItem {
    /// The broker's id for the item; the only thing a delete request names.
    pub expiry_id: ExpiryId,
    /// Where the item was before it was quarantined (display only).
    pub path: String,
    /// Bytes.
    pub bytes: u64,
    /// It holds user data.
    pub user_data: bool,
    /// Its retention has ended; deleting it is the ordinary purge, not a "Delete now".
    pub due: bool,
    /// "2.0 KB · user data · can be put back for 20 more days".
    pub detail: String,
}

impl VaultItem {
    /// The row of one listed item.
    pub fn new(item: &ExpiringItem, clock: &Clock) -> Self {
        let days = clock.days_left(valid(item.expired));
        let mut parts = vec![format_size(item.bytes)];
        if item.user_data {
            parts.push("user data".into());
        }
        parts.push(if item.due || days == 0 {
            "past its retention".into()
        } else {
            format!(
                "can be put back for {days} more {}",
                if days == 1 { "day" } else { "days" }
            )
        });
        Self {
            expiry_id: item.expiry_id,
            path: item.files.first().cloned().unwrap_or_default(),
            bytes: item.bytes,
            user_data: item.user_data,
            due: item.due,
            detail: parts.join(" · "),
        }
    }

    /// The item's "Delete now" button, for a screen reader.
    pub fn delete_label(&self) -> String {
        format!("Delete {} now", self.path)
    }
}
