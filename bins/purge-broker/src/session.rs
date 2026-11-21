//! The broker's in-memory tables (M3 design 3.6): uninstall sessions, scans and plans, each keyed by
//! a random 64-bit id that exists only in this process.
//!
//! An id that is not in its table, or no longer, answers `gone` with the kind of the id. The tables
//! hold what the handlers put in them, behind an `Arc`; the broker core looks at the counts only
//! (the exit rule "no other session open"), and at which scans were made while the local baseline was
//! still building (`baseline.changed` offers them again).
//!
//! - A **session** is one harvest and uninstall of one program. The handler removes it when its change
//!   is done; a completed change ends the broker only when no session is left (design 3.6).
//! - A **scan** stays until the broker ends. Its candidates are keyed by the wire id
//!   (`CandidateRef`): the pipeline drops every candidate of an id that names two targets (review M3-R1
//!   M2), and [`unique_index`] is the check a handler makes before it serves a scan anyway.
//! - A **plan** is used once: [`Table::take`] removes it, so a reused plan id is `gone`.
//!
//! Every table is bounded ([`TABLE_CAP`]): a client that never stops asking cannot grow the broker.

use std::collections::HashMap;
use std::hash::Hash;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use purge_model::ProgramId;
use purge_rpc::error::{ErrorData, ErrorObject, IdKind};
use purge_rpc::methods::{PlanId, ScanId, UninstallSessionId};

/// Most entries in one table.
pub const TABLE_CAP: usize = 256;

/// A broker id: 64 bits with a text form, and the kind `gone` names.
pub trait BrokerId: Copy + Eq + Hash + Send + Sync + 'static {
    /// The kind of id, for `gone`.
    const KIND: IdKind;
    /// The id with these bits.
    fn from_bits(bits: u64) -> Self;
    /// The id's bits.
    fn bits(self) -> u64;
}

macro_rules! broker_id {
    ($t:ty, $kind:expr) => {
        impl BrokerId for $t {
            const KIND: IdKind = $kind;
            fn from_bits(bits: u64) -> Self {
                <$t>::from_bits(bits)
            }
            fn bits(self) -> u64 {
                <$t>::bits(self)
            }
        }
    };
}

broker_id!(UninstallSessionId, IdKind::UninstallSession);
broker_id!(ScanId, IdKind::Scan);
broker_id!(PlanId, IdKind::Plan);

/// The `gone` error for an id of `kind`.
pub fn gone(kind: IdKind) -> ErrorObject {
    ErrorObject::server(ErrorData::Gone { id: kind })
}

/// Where a table's id bits come from.
type IdSource = Box<dyn Fn() -> Result<u64, String> + Send + Sync>;

fn os_ids() -> Result<u64, String> {
    purge_win::os::random_u64().map_err(|e| e.to_string())
}

/// One table of entries keyed by `I`.
pub struct Table<I: BrokerId, V> {
    entries: Mutex<HashMap<u64, Arc<V>>>,
    ids: IdSource,
    _id: PhantomData<fn() -> I>,
}

impl<I: BrokerId, V> Table<I, V> {
    /// An empty table whose ids come from the system's random source.
    pub fn new() -> Self {
        Self::with_ids(Box::new(os_ids))
    }

    /// An empty table with another id source (tests force collisions with it).
    pub fn with_ids(ids: IdSource) -> Self {
        Table {
            entries: Mutex::new(HashMap::new()),
            ids,
            _id: PhantomData,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Arc<V>>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Adds `value` under a new id: one that is not in the table and is not zero. A source that
    /// gives only taken ids ends after a few tries with a `runtime` error; so does a full table.
    pub fn insert(&self, value: V) -> Result<I, ErrorObject> {
        let mut entries = self.lock();
        if entries.len() >= TABLE_CAP {
            return Err(ErrorObject::runtime(format!(
                "the broker holds {TABLE_CAP} {:?} entries already",
                I::KIND
            )));
        }
        for _ in 0..8 {
            let bits = (self.ids)().map_err(ErrorObject::runtime)?;
            if bits != 0 && !entries.contains_key(&bits) {
                entries.insert(bits, Arc::new(value));
                return Ok(I::from_bits(bits));
            }
        }
        Err(ErrorObject::runtime("no free id"))
    }

    /// The entry, or `gone`.
    pub fn get(&self, id: I) -> Result<Arc<V>, ErrorObject> {
        self.lock()
            .get(&id.bits())
            .cloned()
            .ok_or_else(|| gone(I::KIND))
    }

    /// Removes and returns the entry, or `gone`: the id works once.
    pub fn take(&self, id: I) -> Result<Arc<V>, ErrorObject> {
        self.lock().remove(&id.bits()).ok_or_else(|| gone(I::KIND))
    }

    /// Removes the entry; whether it was there.
    pub fn remove(&self, id: I) -> bool {
        self.lock().remove(&id.bits()).is_some()
    }

    /// How many entries.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// The ids, in no order.
    pub fn ids(&self) -> Vec<I> {
        self.lock().keys().map(|b| I::from_bits(*b)).collect()
    }
}

impl<I: BrokerId, V> Default for Table<I, V> {
    fn default() -> Self {
        Self::new()
    }
}

/// A scan in its table, with what the broker core needs to know about it.
#[derive(Debug)]
pub struct ScanSlot<C> {
    /// What the handler stored.
    pub scan: C,
    /// The local baseline was still building when the scan was made: `baseline.changed` offers it
    /// again when the build completes.
    pub during_build: bool,
}

/// The three tables of one broker.
pub struct Tables<S, C, P> {
    /// Uninstall sessions (`session_id`).
    pub sessions: Table<UninstallSessionId, S>,
    /// Scans (`scan_id`).
    pub scans: Table<ScanId, ScanSlot<C>>,
    /// Plans (`plan_id`), used once.
    pub plans: Table<PlanId, P>,
}

impl<S, C, P> Tables<S, C, P> {
    /// Empty tables.
    pub fn new() -> Self {
        Tables {
            sessions: Table::new(),
            scans: Table::new(),
            plans: Table::new(),
        }
    }

    /// Adds a scan; `during_build` says the local baseline build was still running.
    pub fn add_scan(&self, scan: C, during_build: bool) -> Result<ScanId, ErrorObject> {
        self.scans.insert(ScanSlot { scan, during_build })
    }

    /// The scans made while the local baseline was building.
    pub fn scans_to_offer(&self) -> Vec<ScanId> {
        let mut ids: Vec<ScanId> = self
            .scans
            .ids()
            .into_iter()
            .filter(|id| self.scans.get(*id).is_ok_and(|s| s.during_build))
            .collect();
        ids.sort();
        ids
    }
}

impl<S, C, P> Default for Tables<S, C, P> {
    fn default() -> Self {
        Self::new()
    }
}

/// Indexes `items` by `key`. `Err` names the first key two items share: a scan with such a key is not
/// served (review M3-R1 M2: a selection by candidate id must name exactly one target).
pub fn unique_index<T, K: Eq + Hash + Copy>(
    items: &[T],
    key: impl Fn(&T) -> K,
) -> Result<HashMap<K, usize>, K> {
    let mut index = HashMap::with_capacity(items.len());
    for (at, item) in items.iter().enumerate() {
        let k = key(item);
        if index.insert(k, at).is_some() {
            return Err(k);
        }
    }
    Ok(index)
}

/// Whether a program id from the wire may be looked up at all (review M3-R1 S5): its hive is `HKLM` or
/// the checked account's `HKU:<sid>`. The id is only ever compared with the broker's own inventory.
pub fn program_hive_allowed(id: &ProgramId, user_sid: &str) -> bool {
    id.hive_sid()
        .is_none_or(|sid| sid.eq_ignore_ascii_case(user_sid))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use purge_model::View;

    use super::*;

    #[test]
    fn ids_are_random_unique_and_nonzero() {
        let t: Table<ScanId, u32> = Table::new();
        let a = t.insert(1).unwrap();
        let b = t.insert(2).unwrap();
        assert_ne!(a, b);
        assert_ne!(a.bits(), 0);
        assert_eq!(*t.get(a).unwrap(), 1);
        assert_eq!(*t.get(b).unwrap(), 2);
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn a_taken_or_zero_id_is_not_issued_again() {
        let seq = Arc::new(AtomicU64::new(0));
        let s = seq.clone();
        let sequence = [0u64, 7, 7, 7, 9];
        let t: Table<PlanId, &str> = Table::with_ids(Box::new(move || {
            Ok(sequence[(s.fetch_add(1, Ordering::SeqCst) as usize).min(4)])
        }));
        let first = t.insert("a").unwrap();
        assert_eq!(first.bits(), 7, "zero is skipped");
        let second = t.insert("b").unwrap();
        assert_eq!(second.bits(), 9, "7 is taken, so the source is asked again");
        assert_eq!(*t.get(first).unwrap(), "a");

        let stuck: Table<PlanId, u8> = Table::with_ids(Box::new(|| Ok(5)));
        stuck.insert(1).unwrap();
        let e = stuck.insert(2).unwrap_err();
        assert_eq!(e.data.map(|d| d.kind()), Some("runtime"));
        let failing: Table<PlanId, u8> = Table::with_ids(Box::new(|| Err("no random".into())));
        assert!(failing.insert(1).is_err());
    }

    #[test]
    fn unknown_removed_and_taken_ids_are_gone_with_their_kind() {
        let sessions: Table<UninstallSessionId, u8> = Table::new();
        let scans: Table<ScanId, u8> = Table::new();
        let plans: Table<PlanId, u8> = Table::new();
        let kind = |e: ErrorObject| match e.data {
            Some(ErrorData::Gone { id }) => id,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            kind(sessions.get(UninstallSessionId::from_bits(1)).unwrap_err()),
            IdKind::UninstallSession
        );
        assert_eq!(
            kind(scans.get(ScanId::from_bits(1)).unwrap_err()),
            IdKind::Scan
        );
        assert_eq!(
            kind(plans.get(PlanId::from_bits(1)).unwrap_err()),
            IdKind::Plan
        );

        let id = plans.insert(5).unwrap();
        assert_eq!(*plans.take(id).unwrap(), 5);
        assert_eq!(
            kind(plans.take(id).unwrap_err()),
            IdKind::Plan,
            "a plan id works once"
        );
        assert_eq!(kind(plans.get(id).unwrap_err()), IdKind::Plan);

        let id = sessions.insert(1).unwrap();
        assert!(sessions.remove(id));
        assert!(!sessions.remove(id));
        assert_eq!(
            kind(sessions.get(id).unwrap_err()),
            IdKind::UninstallSession
        );
        assert!(sessions.is_empty());
    }

    #[test]
    fn a_table_is_bounded() {
        let t: Table<ScanId, u32> = Table::new();
        for n in 0..TABLE_CAP {
            t.insert(n as u32).unwrap();
        }
        let e = t.insert(0).unwrap_err();
        assert_eq!(e.data.map(|d| d.kind()), Some("runtime"));
        assert_eq!(t.len(), TABLE_CAP);
    }

    #[test]
    fn scans_made_during_the_build_are_offered() {
        let tables: Tables<(), &str, ()> = Tables::new();
        let early = tables.add_scan("early", true).unwrap();
        let _late = tables.add_scan("late", false).unwrap();
        assert_eq!(tables.scans_to_offer(), [early]);
        assert_eq!(tables.scans.get(early).unwrap().scan, "early");
    }

    #[test]
    fn a_shared_candidate_id_is_found() {
        assert_eq!(unique_index(&["a", "b", "c"], |s| *s).unwrap().len(), 3);
        assert_eq!(unique_index(&[1, 2, 1, 3], |n| *n), Err(1));
        assert!(unique_index::<u8, u8>(&[], |n| *n).unwrap().is_empty());
    }

    #[test]
    fn only_hklm_and_the_checked_account_are_looked_up() {
        let me = "S-1-5-21-1-2-3-1001";
        let machine = ProgramId::machine(View::K64, "Git_is1").unwrap();
        let mine = ProgramId::user(me, View::K64, "x").unwrap();
        let other = ProgramId::user("S-1-5-21-1-2-3-1002", View::K64, "x").unwrap();
        let system = ProgramId::user("S-1-5-18", View::K64, "x").unwrap();
        assert!(program_hive_allowed(&machine, me));
        assert!(program_hive_allowed(&mine, me));
        assert!(program_hive_allowed(&mine, &me.to_lowercase()));
        assert!(!program_hive_allowed(&other, me));
        assert!(!program_hive_allowed(&system, me));
    }
}
