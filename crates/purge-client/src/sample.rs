//! The sample engine (port of `Fake/FakeEngineClient.cs`): answers from embedded sample data shaped
//! like the engine's, with no process and no I/O. It backs `--sample`, the launch bench stub, and the
//! fallback when the real engine cannot be used ([`crate::startup`]).
//!
//! It answers on the calling thread, before [`Engine::request`] returns (the bench list after 20 ms on
//! a thread of its own). It changes nothing: [`Engine::can_change_pc`] is false, and routing or
//! running an uninstaller is [`ClientError::NotAvailable`].
//!
//! The sample inventory is `sample/sample-inventory.json`, a `purge.inventory/0` document, turned into
//! rows, patches and details exactly as `bins/purge-engine/src/stdio.rs` does (`row_of`, `patch_of`,
//! `details_of`; no AppX package list, so only a `\WindowsApps\` location marks AppX). The C#
//! client's forecasts and quarantine samples are not ported: they belong to the CLI-era model types
//! the stdio protocol does not have.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use purge_model::BaselineTrust;
use purge_model::{InstallerKind, InventoryDoc, InventoryEntry, ProgramId};
use purge_rpc::methods::{
    ElevationType, HistoryIndex, InventoryChanges, MediumHello, ProgramDetails, ProgramPatch,
    ProgramRef, ProgramRow, ProgramSize, StdioCall,
};
use purge_rpc::{BaselineBuild, BaselineStatus, EngineHello};

use crate::engine::Engine;
use crate::{Answer, CallId, ClientError, ClientEvent, ProgramIcon, ProgramList, Sink};

const INVENTORY: &str = include_str!("../sample/sample-inventory.json");
const SIZES: &str = include_str!("../sample/sample-sizes.json");

/// The answer of every request that would change the PC or need a real engine.
pub const NOT_LIVE: &str =
    "Sample data: no engine is connected, so nothing can be scanned, moved or put back.";

/// The sample user's SID.
const SAMPLE_SID: &str = "S-1-5-21-1000000001-2000000002-3000000003-1001";

/// The sample engine.
pub struct SampleEngine {
    sink: Sink,
    entries: Vec<InventoryEntry>,
    sizes: HashMap<String, u64>,
    bench_rows: usize,
}

impl fmt::Debug for SampleEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SampleEngine")
            .field("entries", &self.entries.len())
            .field("bench_rows", &self.bench_rows)
            .finish_non_exhaustive()
    }
}

impl SampleEngine {
    /// The sample engine. The embedded sample is checked by the tests, so it always reads; were it
    /// broken, the list would be empty rather than the UI failing.
    pub fn new(sink: Sink) -> SampleEngine {
        let entries = serde_json::from_str::<InventoryDoc>(INVENTORY)
            .map(|doc| doc.entries)
            .unwrap_or_default();
        let sizes = serde_json::from_str::<HashMap<String, u64>>(SIZES).unwrap_or_default();
        SampleEngine {
            sink,
            entries,
            sizes,
            bench_rows: 0,
        }
    }

    /// The launch bench stub (M3 design 9.3): when above zero, `programs.list` answers after 20 ms
    /// with this many rows (the sample's, repeated with numbered ids and names), and no icons.
    pub fn with_bench_rows(mut self, rows: usize) -> SampleEngine {
        self.bench_rows = rows;
        self
    }

    /// The sample's `engine.hello`.
    pub fn hello() -> MediumHello {
        MediumHello {
            hello: EngineHello {
                version: "0.0.0-stub".into(),
                elevated: false,
                user_sid: SAMPLE_SID.into(),
                shell_sid: Some(SAMPLE_SID.into()),
                edition: "Professional".into(),
                build: 26300,
                ubr: 0,
                policy_version: "0".into(),
                baseline: BaselineStatus {
                    baseline_available: true,
                    baseline_trust: BaselineTrust::Exact,
                    baseline_view: None,
                    baseline_build: BaselineBuild::None {
                        reason: "sample data".into(),
                    },
                },
            },
            // The usual desktop account: an administrator's limited half.
            elevation_type: ElevationType::Limited,
            shell_matches: true,
        }
    }

    fn list(entries: &[InventoryEntry], bench_rows: usize) -> ProgramList {
        let mut rows = Vec::new();
        let mut patches = Vec::new();
        let mut push = |entry: &InventoryEntry| {
            rows.push(row_of(entry));
            patches.push(patch_of(entry));
        };
        if bench_rows == 0 || entries.is_empty() {
            entries.iter().for_each(&mut push);
        } else {
            for i in 0..bench_rows {
                let src = &entries[i % entries.len()];
                if i < entries.len() {
                    push(src);
                    continue;
                }
                let mut copy = src.clone();
                let key = format!("{}-{i}", src.program_id.key_name());
                copy.program_id = match src.program_id.hive_sid() {
                    None => ProgramId::machine(src.program_id.view(), key),
                    Some(sid) => ProgramId::user(sid.to_owned(), src.program_id.view(), key),
                }
                .unwrap_or_else(|_| src.program_id.clone());
                copy.display_name = format!("{} {i}", src.display_name);
                push(&copy);
            }
        }
        ProgramList { rows, patches }
    }

    fn icons(ids: &[ProgramId], px: u16) -> Vec<ProgramIcon> {
        ids.iter()
            .map(|id| ProgramIcon {
                program_id: id.clone(),
                px,
                bgra: Some(dot(&id.to_string(), px)),
            })
            .collect()
    }

    fn answer(&self, call: CallId, request: &StdioCall) -> Option<Result<Answer, ClientError>> {
        Some(match request {
            StdioCall::EngineHello(_) => Ok(Answer::MediumHello(SampleEngine::hello())),
            StdioCall::ProgramsList(_) => {
                return if self.bench_rows > 0 {
                    let list = SampleEngine::list(&self.entries, self.bench_rows);
                    let sink = self.sink.clone();
                    let spawned = std::thread::Builder::new()
                        .name("purge-sample-bench".into())
                        .spawn(move || {
                            std::thread::sleep(Duration::from_millis(20));
                            sink.send(ClientEvent::Reply {
                                call,
                                result: Ok(Answer::Programs(list)),
                            });
                        });
                    match spawned {
                        Ok(_) => None,
                        Err(e) => Some(Err(ClientError::NotAvailable(e.to_string()))),
                    }
                } else {
                    Some(Ok(Answer::Programs(SampleEngine::list(&self.entries, 0))))
                };
            }
            StdioCall::ProgramsGet(p) => Ok(Answer::Program(
                self.entries
                    .iter()
                    .find(|e| e.program_id == p.program_id)
                    .map(details_of),
            )),
            StdioCall::ProgramsIcons(p) => {
                if self.bench_rows == 0 && p.px >= 2 {
                    let icons = SampleEngine::icons(p.program_ids.as_slice(), p.px);
                    self.sink.send(ClientEvent::Icons { call, icons });
                }
                Ok(Answer::Done)
            }
            StdioCall::ProgramsSizes(p) => {
                let sizes: Vec<ProgramSize> = p
                    .program_ids
                    .as_slice()
                    .iter()
                    .filter_map(|id| {
                        self.sizes.get(&id.to_string()).map(|&bytes| ProgramSize {
                            program_id: id.clone(),
                            bytes: Some(bytes),
                        })
                    })
                    .collect();
                if !sizes.is_empty() {
                    self.sink.send(ClientEvent::Sizes { call, sizes });
                }
                Ok(Answer::Done)
            }
            StdioCall::InventoryChanges(_) => Ok(Answer::InventoryChanges(InventoryChanges {
                disappeared: vec![
                    removed(&format!("HKU:{SAMPLE_SID}|64|Notion"), "Notion"),
                    removed(&format!("HKU:{SAMPLE_SID}|64|slack"), "Slack"),
                ]
                .into_iter()
                .flatten()
                .collect(),
                appeared: Vec::new(),
            })),
            // Sample data stores no list: nothing to forget.
            StdioCall::InventoryForget(_) => Ok(Answer::Done),
            // No sample cleanups: History shows its empty state.
            StdioCall::HistoryIndex(_) => Ok(Answer::HistoryIndex(HistoryIndex {
                sessions: Vec::new(),
                volumes: Vec::new(),
            })),
            StdioCall::UninstallRoute(_) | StdioCall::UninstallRunUser(_) => {
                Err(ClientError::NotAvailable(NOT_LIVE.into()))
            }
        })
    }
}

fn removed(id: &str, name: &str) -> Option<ProgramRef> {
    Some(ProgramRef {
        program_id: id.parse().ok()?,
        name: name.into(),
    })
}

/// A round dot in a colour of the program id's hash (the C# `hash * 31 + c` over UTF-16 units),
/// transparent outside.
fn dot(id: &str, px: u16) -> Vec<u8> {
    let mut hash: i32 = 17;
    for c in id.encode_utf16() {
        hash = hash.wrapping_mul(31).wrapping_add(i32::from(c));
    }
    let h = hash as u32;
    let (b, g, r) = (h as u8, (h >> 8) as u8, (h >> 16) as u8);
    let px = usize::from(px);
    let mid = (px as f64 - 1.0) / 2.0;
    let mut bgra = vec![0u8; px * px * 4];
    for y in 0..px {
        for x in 0..px {
            let (dx, dy) = (x as f64 - mid, y as f64 - mid);
            let inside = dx * dx + dy * dy <= mid * mid;
            let at = (y * px + x) * 4;
            bgra[at..at + 4].copy_from_slice(&[b, g, r, if inside { 255 } else { 0 }]);
        }
    }
    bgra
}

/// As `row_of` in `bins/purge-engine/src/stdio.rs`.
fn row_of(entry: &InventoryEntry) -> ProgramRow {
    ProgramRow {
        program_id: entry.program_id.clone(),
        name: entry.display_name.clone(),
        publisher: entry.publisher.clone(),
        version: entry.version.clone(),
        scope: entry.scope,
        size_bytes: None,
        install_time: entry.install_time_evidence.iter().map(|e| e.time).min(),
    }
}

/// As `details_of` in `bins/purge-engine/src/stdio.rs`.
fn details_of(entry: &InventoryEntry) -> ProgramDetails {
    ProgramDetails {
        row: row_of(entry),
        installer: entry.installer_kind,
        writable_by: entry.writable_by,
        install_location: entry.install_location.clone(),
        uninstall_command: entry.uninstall_string.clone(),
        quiet_uninstall_command: entry.quiet_uninstall_string.clone(),
        product_code: entry.product_code.clone(),
    }
}

/// As `patch_of` in `bins/purge-engine/src/stdio.rs`, with no AppX package list.
fn patch_of(entry: &InventoryEntry) -> ProgramPatch {
    let appx = entry
        .install_location
        .as_deref()
        .is_some_and(|l| l.to_ascii_lowercase().contains("\\windowsapps\\"));
    ProgramPatch {
        program_id: entry.program_id.clone(),
        installer: Some(entry.installer_kind),
        product_code: entry.product_code.clone(),
        bundle: (entry.installer_kind == InstallerKind::Burn).then(|| entry.program_id.clone()),
        appx: appx.then_some(true),
        system_component: entry.flags.system_component.then_some(true),
        unnamed: (!entry.flags.has_display_name).then_some(true),
        parent_key: entry.flags.parent_key.clone(),
    }
}

impl Engine for SampleEngine {
    fn is_live(&self) -> bool {
        false
    }

    fn can_change_pc(&self) -> bool {
        false
    }

    fn request(&self, request: StdioCall) -> CallId {
        let call = CallId::next();
        if let Some(result) = self.answer(call, &request) {
            self.sink.send(ClientEvent::Reply { call, result });
        }
        call
    }

    /// Every answer is already given.
    fn cancel(&self, _: CallId) {}

    fn closed_reason(&self) -> Option<String> {
        None
    }

    fn close(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_rpc::methods::{
        IconsParams, NoParams, NonEmpty, ProgramParams, ProgramsParams, RunUserParams,
    };
    use std::sync::mpsc;

    fn engine(rows: usize) -> (SampleEngine, mpsc::Receiver<ClientEvent>) {
        let (tx, rx) = mpsc::channel();
        let sink = Sink::new(tx, std::sync::Arc::new(|| {}));
        (SampleEngine::new(sink).with_bench_rows(rows), rx)
    }

    fn reply(rx: &mpsc::Receiver<ClientEvent>, want: CallId) -> Result<Answer, ClientError> {
        loop {
            match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
                ClientEvent::Reply { call, result } if call == want => return result,
                _ => {}
            }
        }
    }

    #[test]
    fn the_sample_reads_whole() {
        let doc: InventoryDoc = serde_json::from_str(INVENTORY).unwrap();
        assert_eq!(doc.entries.len(), 32);
        let sizes: HashMap<String, u64> = serde_json::from_str(SIZES).unwrap();
        assert!(sizes.keys().all(|k| k.parse::<ProgramId>().is_ok()));
    }

    #[test]
    fn list_get_sizes_icons_and_changes() {
        let (e, rx) = engine(0);
        assert!(!e.is_live() && !e.can_change_pc());
        let call = e.request(StdioCall::ProgramsList(NoParams {}));
        let Ok(Answer::Programs(list)) = reply(&rx, call) else {
            panic!()
        };
        assert_eq!(list.rows.len(), 32);
        assert_eq!(list.patches.len(), 32);
        let git: ProgramId = "HKLM|64|Git_is1".parse().unwrap();
        let row = list.rows.iter().find(|r| r.program_id == git).unwrap();
        assert_eq!(row.name, "Git");
        assert_eq!(row.install_time, Some(purge_model::FileTime(134369280000000000)));

        let call = e.request(StdioCall::ProgramsGet(ProgramParams {
            program_id: git.clone(),
        }));
        let Ok(Answer::Program(Some(details))) = reply(&rx, call) else {
            panic!()
        };
        assert_eq!(details.installer, InstallerKind::Inno);
        let call = e.request(StdioCall::ProgramsGet(ProgramParams {
            program_id: "HKLM|64|Nope".parse().unwrap(),
        }));
        assert_eq!(reply(&rx, call), Ok(Answer::Program(None)));

        let ids = NonEmpty::new(vec![git.clone(), "HKLM|64|Nope".parse().unwrap()]).unwrap();
        let call = e.request(StdioCall::ProgramsSizes(ProgramsParams {
            program_ids: ids,
        }));
        match rx.recv().unwrap() {
            ClientEvent::Sizes { call: c, sizes } => {
                assert_eq!(c, call);
                assert_eq!(sizes.len(), 1);
                assert_eq!(sizes[0].bytes, Some(358612992));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(reply(&rx, call), Ok(Answer::Done));

        let ids = NonEmpty::new(vec![git]).unwrap();
        let call = e.request(StdioCall::ProgramsIcons(IconsParams {
            program_ids: ids,
            px: 16,
        }));
        match rx.recv().unwrap() {
            ClientEvent::Icons { icons, .. } => {
                let bgra = icons[0].bgra.as_ref().unwrap();
                assert_eq!(bgra.len(), 16 * 16 * 4);
                assert_eq!(bgra[3], 0, "a corner is outside the dot");
                assert_eq!(bgra[(8 * 16 + 8) * 4 + 3], 255, "the middle is inside");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(reply(&rx, call), Ok(Answer::Done));

        let call = e.request(StdioCall::InventoryChanges(NoParams {}));
        let Ok(Answer::InventoryChanges(changes)) = reply(&rx, call) else {
            panic!()
        };
        let names: Vec<_> = changes
            .disappeared
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(names, ["Notion", "Slack"]);
    }

    #[test]
    fn nothing_changes_the_pc() {
        let (e, rx) = engine(0);
        let call = e.request(StdioCall::UninstallRunUser(RunUserParams {
            program_id: "HKLM|64|Git_is1".parse().unwrap(),
            quiet: false,
        }));
        assert_eq!(
            reply(&rx, call),
            Err(ClientError::NotAvailable(NOT_LIVE.into()))
        );
    }

    #[test]
    fn the_bench_stub_repeats_rows_and_sends_no_icons() {
        let (e, rx) = engine(100);
        let call = e.request(StdioCall::ProgramsList(NoParams {}));
        let Ok(Answer::Programs(list)) = reply(&rx, call) else {
            panic!()
        };
        assert_eq!(list.rows.len(), 100);
        let mut ids: Vec<_> = list.rows.iter().map(|r| r.program_id.to_string()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 100);
        let ids = NonEmpty::new(vec![list.rows[0].program_id.clone()]).unwrap();
        let call = e.request(StdioCall::ProgramsIcons(IconsParams {
            program_ids: ids,
            px: 16,
        }));
        assert!(
            matches!(rx.recv().unwrap(), ClientEvent::Reply { call: c, result: Ok(Answer::Done) } if c == call)
        );
    }
}
