//! The sample's cleanups (`--sample`): a `history.index` the [`crate::SampleEngine`] answers, and the
//! read-only broker answers a page needs to show them (`history.get`, `journal.pending`,
//! `quarantine.expiring`). Nothing here changes anything: the UI answers every call that would
//! change the PC (`undo.run`, `journal.resume`, `journal.rollback`, `quarantine.purge`) with
//! [`crate::sample::NOT_LIVE`], and never starts a broker for the sample.
//!
//! The cleanups are dated back from the moment the first of these functions is called, once per
//! process, so their days left read the same every time a page asks and their session ids stay the
//! same between the index and the broker's answers.

use std::sync::OnceLock;

use purge_model::FileTime;
use purge_model::exec::op::{ItemOutcome, OpId};
use purge_model::exec::session::{RetentionClass, SessionId, SessionSummary};
use purge_rpc::methods::{
    ExpiringItem, ExpiringList, ExpiringParams, ExpiryId, HistoryDetail, HistoryIndex, HistoryItem,
    ItemKind, PendingList, VolumeCap,
};
use serde_json::json;

const DAY: i64 = 86_400;
const C_SERIAL: u64 = 0x1234_abcd;
const D_SERIAL: u64 = 0x5678_ef01;

/// One sample cleanup.
struct Sample {
    name: &'static str,
    program: &'static str,
    /// Seconds before now that it started.
    ago: i64,
    state: &'static str,
    undone: u32,
    purged: &'static [&'static str],
    on_d: bool,
    items: &'static [(&'static str, ItemKind, u64)],
}

const SAMPLES: &[Sample] = &[
    Sample {
        name: "Zoom Workplace",
        program: "HKU:S-1-5-21-1000000001-2000000002-3000000003-1001|64|ZoomUMX",
        ago: 2 * DAY - 3 * 3600,
        state: "Committed",
        undone: 0,
        purged: &[],
        on_d: false,
        items: &[
            (
                r"C:\Users\Sample\AppData\Roaming\Zoom",
                ItemKind::Folder,
                18_200_000,
            ),
            (
                r"C:\Users\Sample\AppData\Local\Zoom\logs",
                ItemKind::Folder,
                2_100_000,
            ),
            (r"HKCU\Software\Zoom", ItemKind::RegistryKey, 24_000),
            (
                r"HKCU\Software\Classes\zoommtg",
                ItemKind::RegistryKey,
                3_000,
            ),
            (r"\ZoomUpdateTask-S-1-5-21", ItemKind::Task, 2_000),
            (r"C:\Users\Sample\Desktop\Zoom.lnk", ItemKind::File, 2_000),
        ],
    },
    Sample {
        name: "Notepad++",
        program: "HKLM|64|Notepad++",
        ago: 5 * DAY + 2 * 3600,
        state: "Undone",
        undone: 3,
        purged: &[],
        on_d: false,
        items: &[
            (
                r"C:\Users\Sample\AppData\Roaming\Notepad++",
                ItemKind::Folder,
                410_000,
            ),
            (r"HKCU\Software\Notepad++", ItemKind::RegistryKey, 6_000),
            (
                r"HKLM\SOFTWARE\Classes\*\shell\Notepad++",
                ItemKind::RegistryKey,
                2_000,
            ),
        ],
    },
    Sample {
        name: "CCleaner",
        program: "HKLM|64|CCleaner",
        ago: 9 * DAY + 5 * 3600,
        state: "Committed",
        undone: 0,
        purged: &[],
        on_d: false,
        items: &[
            (r"C:\Program Files\CCleaner", ItemKind::Folder, 310_000),
            (r"HKLM\SOFTWARE\Piriform", ItemKind::RegistryKey, 8_000),
            (r"HKCU\Software\Piriform", ItemKind::RegistryKey, 4_000),
            (r"\CCleaner Update", ItemKind::Task, 2_000),
        ],
    },
    Sample {
        name: "Microsoft Visual Studio Code",
        program: "HKU:S-1-5-21-1000000001-2000000002-3000000003-1001|64|{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1",
        ago: 12 * DAY + 3600,
        state: "Open",
        undone: 0,
        purged: &[],
        on_d: false,
        items: &[
            (
                r"C:\Users\Sample\AppData\Roaming\Code",
                ItemKind::Folder,
                21_000_000,
            ),
            (r"C:\Users\Sample\.vscode", ItemKind::Folder, 8_400_000),
        ],
    },
    Sample {
        name: "WinRAR 6.24",
        program: "HKLM|64|WinRAR archiver",
        ago: 17 * DAY + 7 * 3600,
        state: "PartiallyUndone",
        undone: 1,
        purged: &[],
        on_d: false,
        items: &[
            (r"C:\Program Files\WinRAR", ItemKind::Folder, 9_400_000),
            (r"HKLM\SOFTWARE\WinRAR", ItemKind::RegistryKey, 12_000),
            (r"HKCU\Software\WinRAR", ItemKind::RegistryKey, 6_000),
        ],
    },
    Sample {
        name: "Skype",
        program: "HKU:S-1-5-21-1000000001-2000000002-3000000003-1001|64|Skype_is1",
        ago: 26 * DAY + 4 * 3600,
        state: "Committed",
        undone: 0,
        purged: &[],
        on_d: true,
        items: &[
            (
                r"D:\Users\Sample\AppData\Roaming\Skype",
                ItemKind::Folder,
                44_000_000,
            ),
            (r"HKCU\Software\Skype", ItemKind::RegistryKey, 9_000),
        ],
    },
    Sample {
        name: "iTunes",
        program: "HKLM|64|{D6E2B8F1-1E1B-4B6B-9C38-3B2C8C3B7A11}",
        ago: 33 * DAY + 6 * 3600,
        state: "Committed",
        undone: 0,
        purged: &[],
        on_d: false,
        items: &[
            (
                r"C:\ProgramData\Apple Computer\iTunes",
                ItemKind::Folder,
                1_200_000,
            ),
            (
                r"HKLM\SOFTWARE\Apple Computer, Inc.\iTunes",
                ItemKind::RegistryKey,
                30_000,
            ),
        ],
    },
    Sample {
        name: "Adobe Reader XI",
        program: "HKLM|32|{AC76BA86-7AD7-1033-7B44-AB0000000001}",
        ago: 64 * DAY,
        state: "Committed",
        undone: 0,
        purged: &["Quarantine"],
        on_d: false,
        items: &[
            (
                r"C:\Program Files (x86)\Adobe\Reader 11.0",
                ItemKind::Folder,
                0,
            ),
            (
                r"HKLM\SOFTWARE\WOW6432Node\Adobe\Acrobat Reader",
                ItemKind::RegistryKey,
                41_000,
            ),
        ],
    },
];

/// The moment the samples are dated from: the first call in this process.
fn anchor() -> i64 {
    static NOW: OnceLock<i64> = OnceLock::new();
    *NOW.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(0))
            .unwrap_or(0)
    })
}

fn started(s: &Sample) -> FileTime {
    FileTime::from_unix_secs(anchor() - s.ago)
}

fn id_of(at: usize, s: &Sample) -> SessionId {
    SessionId::new(
        started(s),
        0x5a3e_1e00_0000_0000_u64.wrapping_add(at as u64 + 1),
    )
}

/// The bytes a sample still holds: none once its files and backups are both gone or put back.
fn held(s: &Sample) -> u64 {
    if s.state == "Undone" {
        return 0;
    }
    let files_gone = s.purged.contains(&"Quarantine");
    s.items
        .iter()
        .filter(|(_, kind, _)| !(files_gone && matches!(kind, ItemKind::Folder | ItemKind::File)))
        .map(|(_, _, b)| b)
        .sum()
}

fn summary(at: usize, s: &Sample) -> Option<SessionSummary> {
    let start = started(s);
    let after = |days: i64| (anchor() - s.ago + days * DAY);
    let n = s.items.len() as u32;
    let bytes = held(s);
    let (serial, root) = if s.on_d {
        (D_SERIAL, "D:\\")
    } else {
        (C_SERIAL, "C:\\")
    };
    let finished = (s.state != "Open").then(|| start.0 + 600 * 10_000_000);
    let value = json!({
        "id": id_of(at, s),
        "app": s.program,
        "owner": { "program_id": s.program, "display_name": s.name },
        "plan_hash": format!("{:064x}", at + 1),
        "state": s.state,
        "started": start.0,
        "finished": finished,
        "counts": {
            "done": if s.state == "Open" { n - 1 } else { n },
            "vanished": 0, "skipped": 0, "held_retry": 0, "pending_reboot": 0, "failed": 0
        },
        "undone": s.undone,
        "backup_bytes": bytes,
        "usage": [{ "serial": serial, "root": root, "bytes": bytes }],
        "expires": {
            "quarantine": FileTime::from_unix_secs(after(i64::from(RetentionClass::Quarantine.days()))).0,
            "backups": FileTime::from_unix_secs(after(i64::from(RetentionClass::Backup.days()))).0,
            "journal": FileTime::from_unix_secs(after(365)).0
        },
        "purged": s.purged,
        "pending_reboot": false
    });
    serde_json::from_value(value).ok()
}

/// The sample's `history.index`: eight cleanups over two months, one of them interrupted, one
/// past its file retention, one whose files were deleted, and one put back.
pub fn index() -> HistoryIndex {
    let sessions: Vec<SessionSummary> = SAMPLES
        .iter()
        .enumerate()
        .filter_map(|(at, s)| summary(at, s))
        .collect();
    let used = |serial: u64| -> u64 {
        sessions
            .iter()
            .flat_map(|s| s.usage.iter())
            .filter(|u| u.serial == serial)
            .map(|u| u.bytes)
            .sum()
    };
    let cap = 10 * 1024 * 1024 * 1024;
    HistoryIndex {
        volumes: vec![
            VolumeCap {
                serial: C_SERIAL,
                root: "C:\\".into(),
                used: used(C_SERIAL),
                cap,
            },
            VolumeCap {
                serial: D_SERIAL,
                root: "D:\\".into(),
                used: used(D_SERIAL),
                cap,
            },
        ],
        sessions,
    }
}

fn find(session: &SessionId) -> Option<(usize, &'static Sample)> {
    SAMPLES
        .iter()
        .enumerate()
        .find(|(at, s)| &id_of(*at, s) == session)
}

/// The sample's `history.get` of one cleanup; `None` for a session it does not have (`gone`).
pub fn detail(session: &SessionId) -> Option<HistoryDetail> {
    let (at, s) = find(session)?;
    let summary = summary(at, s)?;
    let files_gone = s.purged.contains(&"Quarantine");
    let items = s
        .items
        .iter()
        .enumerate()
        .map(|(i, (path, kind, _))| {
            let file = matches!(kind, ItemKind::Folder | ItemKind::File);
            HistoryItem {
                op: OpId(i as u32 + 1),
                display_name: (*path).into(),
                kind: *kind,
                outcome: if s.state == "Open" && i + 1 == s.items.len() {
                    ItemOutcome::HeldRetry
                } else {
                    ItemOutcome::Done
                },
                undone: s.state == "Undone" || (i as u32) < s.undone,
                alert: None,
                deleted: (files_gone && file).then_some(purge_rpc::methods::Deleted::Expired),
            }
        })
        .collect();
    Some(HistoryDetail {
        session: session.clone(),
        state: summary.state,
        items,
    })
}

/// The sample's `journal.pending`: the interrupted cleanup is already in the index, so nothing more.
pub fn pending() -> PendingList {
    PendingList {
        sessions: Vec::new(),
    }
}

/// The sample's `quarantine.expiring`: what is due, and with `include_not_due` every quarantined
/// file still held (and with `include_backups_not_due` the registry backups too).
pub fn expiring(params: &ExpiringParams) -> ExpiringList {
    let mut items = Vec::new();
    let mut next = 0u64;
    for (at, s) in SAMPLES.iter().enumerate() {
        let Some(summary) = summary(at, s) else {
            continue;
        };
        if !matches!(s.state, "Committed" | "PartiallyUndone") {
            continue;
        }
        let now = FileTime::from_unix_secs(anchor());
        for (i, (path, kind, bytes)) in s.items.iter().enumerate() {
            next += 1;
            if (i as u32) < s.undone {
                continue;
            }
            let file = matches!(kind, ItemKind::Folder | ItemKind::File);
            let class = if file {
                RetentionClass::Quarantine
            } else {
                RetentionClass::Backup
            };
            if file && s.purged.contains(&"Quarantine") {
                continue;
            }
            let expired = if file {
                summary.expires.quarantine
            } else {
                summary.expires.backups
            };
            let due = expired <= now;
            let wanted = due
                || (file && params.include_not_due)
                || (!file && params.include_backups_not_due);
            if !wanted {
                continue;
            }
            let Ok(expiry_id) = format!("e-{:016x}", 0xe000 + next).parse::<ExpiryId>() else {
                continue;
            };
            items.push(ExpiringItem {
                expiry_id,
                session: summary.id.clone(),
                app: s.name.into(),
                class,
                expired,
                due,
                files: vec![(*path).into()],
                bytes: *bytes,
                user_data: path.contains("AppData"),
            });
        }
    }
    ExpiringList { items }
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_model::exec::session::SessionState;

    #[test]
    fn every_sample_reads_and_keeps_its_id_between_the_index_and_the_broker() {
        let index = index();
        assert_eq!(index.sessions.len(), SAMPLES.len());
        assert!(index.sessions.iter().any(|s| s.state == SessionState::Open));
        for s in &index.sessions {
            let d = detail(&s.id).expect("each listed cleanup has its items");
            assert!(!d.items.is_empty());
        }
        assert_eq!(index.sessions[0].id, super::index().sessions[0].id);
    }

    #[test]
    fn only_what_is_due_is_listed_unless_more_is_asked_for() {
        let due = expiring(&ExpiringParams::default());
        assert!(!due.items.is_empty(), "iTunes is past its file retention");
        assert!(due.items.iter().all(|i| i.due));
        let all = expiring(&ExpiringParams {
            include_not_due: true,
            include_backups_not_due: false,
        });
        assert!(all.items.len() > due.items.len());
        assert!(
            all.items
                .iter()
                .all(|i| i.due || i.class == RetentionClass::Quarantine)
        );
    }
}
