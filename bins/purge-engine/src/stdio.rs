//! The medium engine's `--stdio` server (M3_DESIGN.md §6.3, package M3-STDIO).
//!
//! The server answers the Read and UserRun methods of the method table over newline-delimited
//! JSON-RPC on stdin/stdout. It starts no scan and no harvest and writes nothing outside
//! `%LOCALAPPDATA%\Purge`; the only file it writes there is the stored program list that
//! `inventory.changes` compares against.
//!
//! # Cancellation
//!
//! [`serve`] reads lines on one thread and runs requests on the calling thread. A `$/cancel` reaches
//! the server while a cancellable request runs (the reader thread records it in [`Cancellation`]),
//! and the request's loops stop at the next batch. A cancel for a method the table marks
//! non-cancellable is refused: it changes nothing. [`serve_stdio`] is the same over the process's
//! stdin and stdout.
//!
//! # Extension points
//!
//! `programs.icons` (M3-ICONS) and `uninstall.route` / `uninstall.run_user` (M3-RUNNER) belong to
//! other packages. They plug in through [`Extension`]: a server built with one or more extensions
//! offers every decoded request to them first. Without an extension those three methods answer a
//! `runtime` error that names the package, so the rest of the server works on its own.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use purge_model::cap::cap_bytes;
use purge_model::exec::session::{SessionIndex, SessionSummary};
use purge_model::{InventoryDoc, InventoryEntry};
use purge_rpc::error::{ErrorData, ErrorObject, IdKind};
use purge_rpc::frame::{FrameError, FrameReader, FrameWriter, RequestId, Response};
use purge_rpc::methods::{
    HistoryIndex, InventoryChanges, MediumHello, ProgramDetails, ProgramParams, ProgramPatch,
    ProgramRef, ProgramRow, ProgramSize, ProgramsBatch, ProgramsParams, ProgramsPatch,
    ServerNotification, SizeReady, Started, StdioCall, VolumeCap,
};
use purge_rpc::sets::{OUT_LIMIT, STDIO_IN_LIMIT, Transport};
use purge_rpc::table::{self, CallSet, Dispatcher, Notify, Routed};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::pipeline::{self, Settings, Sources};

/// How many raw ARP rows one `programs.batch` line carries.
const ROWS_PER_BATCH: usize = 50;
/// How many patches one `programs.patch` line carries.
const PATCHES_PER_BATCH: usize = 500;
/// How many sizes one `size.ready` line carries.
const SIZES_PER_BATCH: usize = 256;
/// Where the last program list is stored, under the local data directory.
const STORED_LIST_FILE: &str = "inventory.json";
/// The schema id of [`StoredList`].
const STORED_LIST_SCHEMA: &str = "purge.inventory-list/1";
/// The largest session index the medium server reads (`index.json` is 64 MiB for purge-exec too).
const MAX_INDEX_BYTES: u64 = 64 << 20;
/// The deepest folder walk `programs.sizes` makes under one install root.
const SIZE_WALK_DEPTH: usize = 32;

/// An optional handler for methods another package owns.
///
/// [`Server::call`] offers every decoded call to each extension in turn; the first `Some` is the
/// answer. An extension matches on [`StdioCall::method`] and returns `None` for methods it does not
/// handle. Notifications go through `notify`.
pub trait Extension: Send {
    /// Handles `call`, or returns `None`.
    fn call(
        &mut self,
        id: RequestId,
        call: &StdioCall,
        notify: &mut dyn Notify,
    ) -> Option<Result<Value, ErrorObject>>;
}

/// The `programs.list` file `inventory.changes` compares against, under `%LOCALAPPDATA%\Purge`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredList {
    /// Always [`STORED_LIST_SCHEMA`].
    schema: String,
    /// The programs as the last `programs.list` sent them.
    programs: Vec<ProgramRef>,
}

/// The state of one request's cancellation.
#[derive(Debug, Default)]
struct CancelState {
    /// Requests seen on the reader thread, and whether their method is cancellable.
    seen: HashMap<RequestId, bool>,
    /// A pending cancel of a request that has not begun yet.
    pending: HashSet<RequestId>,
    /// The request running now.
    active: Option<Active>,
}

/// The request running now.
#[derive(Debug)]
struct Active {
    /// Its id.
    id: RequestId,
    /// Whether the table lets `$/cancel` stop it.
    cancellable: bool,
    /// Whether a cancel arrived.
    cancelled: bool,
}

/// The cancellation state shared by the reader thread and the request thread.
#[derive(Debug, Clone, Default)]
struct Cancellation {
    state: Arc<Mutex<CancelState>>,
}

impl Cancellation {
    fn lock(&self) -> MutexGuard<'_, CancelState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The reader saw a request line.
    fn seen(&self, id: RequestId, cancellable: bool) {
        self.lock().seen.insert(id, cancellable);
    }

    /// `$/cancel {request}`: stop it if it is cancellable and still runs or waits to begin.
    fn cancel(&self, id: RequestId) {
        let mut state = self.lock();
        if let Some(active) = state.active.as_mut() {
            if active.id == id {
                if active.cancellable {
                    active.cancelled = true;
                }
                return;
            }
        }
        if state.seen.get(&id) == Some(&true) {
            state.pending.insert(id);
        }
    }

    /// A request begins.
    fn begin(&self, id: RequestId, cancellable: bool) {
        let mut state = self.lock();
        let cancelled = cancellable && state.pending.remove(&id);
        state.active = Some(Active {
            id,
            cancellable,
            cancelled,
        });
    }

    /// A request ended.
    fn end(&self, id: RequestId) {
        let mut state = self.lock();
        if state.active.as_ref().is_some_and(|a| a.id == id) {
            state.active = None;
        }
        state.seen.remove(&id);
        state.pending.remove(&id);
    }

    /// Whether the running request was cancelled.
    fn cancelled(&self) -> bool {
        self.lock().active.as_ref().is_some_and(|a| a.cancelled)
    }
}

/// A server over one machine's sources.
pub struct Server<'a> {
    sources: Sources<'a>,
    settings: Settings,
    /// `%LOCALAPPDATA%\Purge`, where the stored list lives.
    local_data: Option<PathBuf>,
    /// The inventory read for this server, once a request needed it.
    inventory: Option<InventoryDoc>,
    extensions: Vec<Box<dyn Extension>>,
    cancellation: Cancellation,
}

impl<'a> Server<'a> {
    /// A server over `sources` with `settings`; the stored list is not written when `local_data` is
    /// `None`.
    pub fn new(sources: Sources<'a>, settings: Settings, local_data: Option<PathBuf>) -> Self {
        Self {
            sources,
            settings,
            local_data,
            inventory: None,
            extensions: Vec::new(),
            cancellation: Cancellation::default(),
        }
    }

    /// A server of the running machine: the stored list goes to `%LOCALAPPDATA%\Purge`.
    pub fn live(sources: Sources<'a>, settings: Settings) -> Self {
        let local = purge_win::known_folders::known_folder(
            purge_win::known_folders::KnownFolder::LocalAppData,
        )
        .ok()
        .map(|dir| dir.join("Purge"));
        Self::new(sources, settings, local)
    }

    /// Adds a handler for methods another package owns.
    pub fn with_extension(mut self, extension: Box<dyn Extension>) -> Self {
        self.extensions.push(extension);
        self
    }

    /// Reads the inventory now, so the first `programs.list` after the server is ready sends its first
    /// batch without paying for the enumeration. `--stdio` calls this before it reads the first
    /// request: the S1 first paint and the 50 ms rule are about the request, not process start.
    pub fn warm(&mut self) {
        let _ = self.inventory();
    }

    /// The inventory of this machine, read once per server.
    fn inventory(&mut self) -> &InventoryDoc {
        self.inventory
            .get_or_insert_with(|| pipeline::inventory(self.sources).doc)
    }

    fn list(&mut self, id: RequestId, notify: &mut dyn Notify) -> Result<Value, ErrorObject> {
        let rows: Vec<ProgramRow> = self.inventory().entries.iter().map(row_of).collect();

        let mut sent = 0u32;
        for batch in rows.chunks(ROWS_PER_BATCH) {
            if self.cancellation.cancelled() {
                return serde_json::to_value(Started { count: sent })
                    .map_err(|e| ErrorObject::runtime(e.to_string()));
            }
            notify
                .notify(&ServerNotification::ProgramsBatch(ProgramsBatch {
                    request: id,
                    rows: batch.to_vec(),
                }))
                .map_err(notify_error)?;
            sent += u32::try_from(batch.len()).unwrap_or(u32::MAX);
        }

        // Patches need the AppX package list, which is a WinRT enumeration of its own: after the raw
        // rows, never on the first batch's path.
        let patches: Vec<ProgramPatch> = {
            let packages = self.sources.sys.packages().unwrap_or_default();
            self.inventory()
                .entries
                .iter()
                .map(|entry| patch_of(entry, &packages))
                .collect()
        };
        for batch in patches.chunks(PATCHES_PER_BATCH) {
            if self.cancellation.cancelled() {
                break;
            }
            notify
                .notify(&ServerNotification::ProgramsPatch(ProgramsPatch {
                    request: id,
                    patches: batch.to_vec(),
                }))
                .map_err(notify_error)?;
        }
        if !self.cancellation.cancelled() {
            self.store_list(&rows);
        }
        serde_json::to_value(Started { count: sent })
            .map_err(|e| ErrorObject::runtime(e.to_string()))
    }

    fn get(&mut self, params: ProgramParams) -> Result<Value, ErrorObject> {
        let entry = self.inventory().entry(&params.program_id).ok_or_else(|| {
            ErrorObject::server(ErrorData::Gone {
                id: IdKind::Program,
            })
        })?;
        serde_json::to_value(details_of(entry)).map_err(|e| ErrorObject::runtime(e.to_string()))
    }

    fn sizes(
        &mut self,
        id: RequestId,
        params: ProgramsParams,
        notify: &mut dyn Notify,
    ) -> Result<Value, ErrorObject> {
        let ids = params.program_ids.as_slice();
        let mut sent = 0usize;
        for chunk in ids.chunks(SIZES_PER_BATCH) {
            if self.cancellation.cancelled() {
                break;
            }
            let mut sizes = Vec::with_capacity(chunk.len());
            for program_id in chunk {
                let base = self
                    .inventory()
                    .entry(program_id)
                    .and_then(|entry| entry.install_location.clone());
                let bytes = base
                    .as_deref()
                    .map(|base| dir_bytes(self.sources.fs, base, 0, &self.cancellation));
                sizes.push(ProgramSize {
                    program_id: program_id.clone(),
                    bytes,
                });
            }
            sent += sizes.len();
            notify
                .notify(&ServerNotification::SizeReady(SizeReady {
                    request: id,
                    sizes,
                }))
                .map_err(notify_error)?;
        }
        serde_json::to_value(Started {
            count: u32::try_from(sent).unwrap_or(u32::MAX),
        })
        .map_err(|e| ErrorObject::runtime(e.to_string()))
    }

    fn changes(&mut self) -> Result<Value, ErrorObject> {
        let current: Vec<ProgramRef> = self
            .inventory()
            .entries
            .iter()
            .map(|entry| ProgramRef {
                program_id: entry.program_id.clone(),
                name: entry.display_name.clone(),
            })
            .collect();
        let stored = self.read_stored()?;
        let disappeared = stored
            .as_ref()
            .map(|list| {
                list.programs
                    .iter()
                    .filter(|p| !current.iter().any(|c| c.program_id == p.program_id))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let appeared = stored
            .map(|list| {
                current
                    .iter()
                    .filter(|p| !list.programs.iter().any(|s| s.program_id == p.program_id))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        serde_json::to_value(InventoryChanges {
            disappeared,
            appeared,
        })
        .map_err(|e| ErrorObject::runtime(e.to_string()))
    }

    fn history(&self) -> Result<Value, ErrorObject> {
        let index = self.read_index()?;
        let mut sessions: Vec<SessionSummary> = index.sessions.clone();
        sessions.reverse();
        let mut volumes: BTreeMap<u64, VolumeCap> = BTreeMap::new();
        for session in &index.sessions {
            for usage in &session.usage {
                volumes.entry(usage.serial).or_insert_with(|| {
                    let root = if usage.root.is_empty() {
                        self.settings
                            .data_root
                            .as_ref()
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_default()
                    } else {
                        usage.root.clone()
                    };
                    let total = if root.is_empty() {
                        0
                    } else {
                        purge_win::fs::volume_total_bytes(Path::new(&root)).unwrap_or(0)
                    };
                    VolumeCap {
                        serial: usage.serial,
                        root,
                        used: index.bytes_on_volume(usage.serial),
                        cap: cap_bytes(total),
                    }
                });
            }
        }
        serde_json::to_value(HistoryIndex {
            sessions,
            volumes: volumes.into_values().collect(),
        })
        .map_err(|e| ErrorObject::runtime(e.to_string()))
    }

    fn read_index(&self) -> Result<SessionIndex, ErrorObject> {
        let Some(root) = self.settings.data_root.as_deref() else {
            return Ok(SessionIndex::default());
        };
        let path = root.join("sessions").join("index.json");
        let text = match std::fs::metadata(&path) {
            Ok(meta) if meta.len() > MAX_INDEX_BYTES => {
                return Err(ErrorObject::runtime(format!(
                    "{} is over the {MAX_INDEX_BYTES}-byte limit",
                    path.display()
                )));
            }
            Ok(_) => std::fs::read_to_string(&path).map_err(|e| {
                ErrorObject::runtime(format!("cannot read {}: {e}", path.display()))
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SessionIndex::default());
            }
            Err(e) => {
                return Err(ErrorObject::runtime(format!(
                    "cannot read {}: {e}",
                    path.display()
                )));
            }
        };
        serde_json::from_str(&text).map_err(|e| {
            ErrorObject::runtime(format!("{} is not a session index: {e}", path.display()))
        })
    }

    fn stored_list_path(&self) -> Option<PathBuf> {
        self.local_data
            .as_ref()
            .map(|dir| dir.join(STORED_LIST_FILE))
    }

    fn read_stored(&self) -> Result<Option<StoredList>, ErrorObject> {
        let Some(path) = self.stored_list_path() else {
            return Ok(None);
        };
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(ErrorObject::runtime(format!(
                    "cannot read {}: {e}",
                    path.display()
                )));
            }
        };
        let list: StoredList = serde_json::from_str(&text).map_err(|e| {
            ErrorObject::runtime(format!(
                "{} is not a stored program list: {e}",
                path.display()
            ))
        })?;
        if list.schema != STORED_LIST_SCHEMA {
            return Err(ErrorObject::runtime(format!(
                "{} has schema {:?}, not {STORED_LIST_SCHEMA:?}",
                path.display(),
                list.schema
            )));
        }
        Ok(Some(list))
    }

    /// Writes the list for the next `inventory.changes`. A failure is not a list failure: the file is
    /// display-only state.
    fn store_list(&self, rows: &[ProgramRow]) {
        let Some(path) = self.stored_list_path() else {
            return;
        };
        let Some(dir) = path.parent() else {
            return;
        };
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }
        let list = StoredList {
            schema: STORED_LIST_SCHEMA.to_owned(),
            programs: rows
                .iter()
                .map(|row| ProgramRef {
                    program_id: row.program_id.clone(),
                    name: row.name.clone(),
                })
                .collect(),
        };
        let Ok(text) = serde_json::to_string(&list) else {
            return;
        };
        let _ = crate::cli::output::write_atomic(&path, &text);
    }

    fn hello(&self) -> Result<Value, ErrorObject> {
        let mut warnings = Vec::new();
        let mut hello = pipeline::hello(self.sources, &self.settings, &mut warnings);
        let facts = purge_win::token::current_process_facts().ok();
        let shell = purge_win::token::shell_owner_facts().ok().flatten();
        if let Some(shell) = &shell {
            if shell.user_sid != hello.user_sid {
                hello.shell_sid = Some(shell.user_sid.clone());
            }
        }
        let elevation_type = facts
            .as_ref()
            .map(|f| elevation_type(f.elevation_type))
            .unwrap_or(purge_rpc::methods::ElevationType::Default);
        let shell_matches = match (&facts, &shell) {
            (Some(own), Some(shell)) => own.same_user_and_elevation(shell),
            _ => false,
        };
        serde_json::to_value(MediumHello {
            hello,
            elevation_type,
            shell_matches,
        })
        .map_err(|e| ErrorObject::runtime(e.to_string()))
    }

    fn call_extensions(
        &mut self,
        id: RequestId,
        call: &StdioCall,
        notify: &mut dyn Notify,
    ) -> Option<Result<Value, ErrorObject>> {
        for extension in &mut self.extensions {
            if let Some(result) = extension.call(id, call, notify) {
                return Some(result);
            }
        }
        None
    }
}

impl Dispatcher for Server<'_> {
    type Call = StdioCall;

    fn call(
        &mut self,
        id: RequestId,
        call: StdioCall,
        notify: &mut dyn Notify,
    ) -> Result<Value, ErrorObject> {
        let cancellable = call.method().spec().cancellable;
        self.cancellation.begin(id, cancellable);
        if self.cancellation.cancelled() {
            self.cancellation.end(id);
            return serde_json::to_value(Started { count: 0 })
                .map_err(|e| ErrorObject::runtime(e.to_string()));
        }
        if let Some(result) = self.call_extensions(id, &call, notify) {
            self.cancellation.end(id);
            return result;
        }
        let result = match call {
            StdioCall::EngineHello(_) => self.hello(),
            StdioCall::ProgramsList(_) => self.list(id, notify),
            StdioCall::ProgramsGet(params) => self.get(params),
            StdioCall::ProgramsSizes(params) => self.sizes(id, params, notify),
            StdioCall::InventoryChanges(_) => self.changes(),
            StdioCall::HistoryIndex(_) => self.history(),
            StdioCall::ProgramsIcons(_) => Err(not_installed("M3-ICONS", "programs.icons")),
            StdioCall::UninstallRoute(_) => Err(not_installed("M3-RUNNER", "uninstall.route")),
            StdioCall::UninstallRunUser(_) => Err(not_installed("M3-RUNNER", "uninstall.run_user")),
        };
        self.cancellation.end(id);
        result
    }

    fn cancel(&mut self, request: RequestId) {
        self.cancellation.cancel(request);
    }
}

/// Why a method another package owns is not in this server.
fn not_installed(package: &str, method: &str) -> ErrorObject {
    ErrorObject::runtime(format!(
        "{method} is provided by {package}, which is not linked into this engine"
    ))
}

fn notify_error(error: FrameError) -> ErrorObject {
    ErrorObject::runtime(format!("cannot send a notification: {error}"))
}

fn elevation_type(kind: purge_win::token::ElevationType) -> purge_rpc::methods::ElevationType {
    use purge_rpc::methods::ElevationType as Wire;
    match kind {
        purge_win::token::ElevationType::Default => Wire::Default,
        purge_win::token::ElevationType::Full => Wire::Full,
        purge_win::token::ElevationType::Limited => Wire::Limited,
    }
}

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

fn patch_of(entry: &InventoryEntry, packages: &[purge_source::types::PackageInfo]) -> ProgramPatch {
    let appx = entry
        .install_location
        .as_deref()
        .is_some_and(|location| is_appx_location(location, packages));
    ProgramPatch {
        program_id: entry.program_id.clone(),
        installer: Some(entry.installer_kind),
        product_code: entry.product_code.clone(),
        // A Burn bundle is the bundle its own row names; child packages have no ARP row of their own
        // in M3's inventory.
        bundle: (entry.installer_kind == purge_model::InstallerKind::Burn)
            .then(|| entry.program_id.clone()),
        appx: appx.then_some(true),
    }
}

fn is_appx_location(location: &str, packages: &[purge_source::types::PackageInfo]) -> bool {
    let location = location.trim_end_matches('\\');
    if location.to_ascii_lowercase().contains("\\windowsapps\\") {
        return true;
    }
    packages.iter().any(|package| {
        package
            .install_location
            .as_deref()
            .is_some_and(|base| under(base.trim_end_matches('\\'), location))
            || package
                .external_location
                .as_deref()
                .is_some_and(|base| under(base.trim_end_matches('\\'), location))
    })
}

/// Whether `path` is `base` or below it, case-insensitively.
fn under(base: &str, path: &str) -> bool {
    if base.is_empty() {
        return false;
    }
    let base = base.to_ascii_lowercase();
    let path = path.to_ascii_lowercase();
    path == base
        || (path.len() > base.len()
            && path.starts_with(&base)
            && path.as_bytes().get(base.len()) == Some(&b'\\'))
}

/// Bytes of the regular files below `base`, never following a reparse point.
fn dir_bytes(
    fs: &dyn purge_source::filesystem::FileSystemSource,
    base: &str,
    depth: usize,
    cancellation: &Cancellation,
) -> u64 {
    if depth > SIZE_WALK_DEPTH || cancellation.cancelled() {
        return 0;
    }
    let Ok(entries) = fs.list_dir(base) else {
        return 0;
    };
    let mut total = 0u64;
    for entry in entries {
        if cancellation.cancelled() {
            return total;
        }
        if entry.meta.is_dir() {
            if !entry.meta.is_reparse_point() {
                total = total.saturating_add(dir_bytes(
                    fs,
                    &join_path(base, &entry.name),
                    depth + 1,
                    cancellation,
                ));
            }
        } else {
            total = total.saturating_add(entry.meta.size);
        }
    }
    total
}

fn join_path(base: &str, name: &str) -> String {
    if base.ends_with('\\') || base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}\\{name}")
    }
}

/// One line the reader thread hands to the request thread.
enum Event {
    /// A decoded request.
    Call(RequestId, StdioCall),
    /// A response that needs no handler (an envelope or params error).
    Reply(Response),
    /// The stream ended cleanly.
    Eof,
    /// The stream cannot go on.
    Failed(FrameError),
}

/// Reads lines and hands them to the request thread; `$/cancel` is acted on at once.
fn read_loop<R: BufRead>(reader: R, sender: &Sender<Event>, cancellation: &Cancellation) {
    let mut reader = FrameReader::new(reader, STDIO_IN_LIMIT);
    loop {
        match reader.read_line() {
            Ok(Some(line)) => match table::route::<StdioCall>(line) {
                Routed::Call { id, call } => {
                    cancellation.seen(id, call.method().spec().cancellable);
                    if sender.send(Event::Call(id, call)).is_err() {
                        return;
                    }
                }
                Routed::Cancel { request } => cancellation.cancel(request),
                Routed::Reply(response) => {
                    if sender.send(Event::Reply(response)).is_err() {
                        return;
                    }
                }
                Routed::Ignored => {}
            },
            Ok(None) => {
                let _ = sender.send(Event::Eof);
                return;
            }
            Err(error) => {
                let _ = sender.send(Event::Failed(error));
                return;
            }
        }
    }
}

struct WriterNotify<'a, W: Write> {
    writer: &'a mut FrameWriter<W>,
}

impl<W: Write> Notify for WriterNotify<'_, W> {
    fn notify(&mut self, notification: &ServerNotification) -> Result<(), FrameError> {
        table::write_notification(self.writer, Transport::Stdio, notification)
    }
}

fn drive<W: Write>(
    receiver: Receiver<Event>,
    writer: W,
    server: &mut Server<'_>,
) -> Result<(), FrameError> {
    let mut writer = FrameWriter::new(writer, OUT_LIMIT);
    while let Ok(event) = receiver.recv() {
        match event {
            Event::Call(id, call) => {
                let body = server.call(
                    id,
                    call,
                    &mut WriterNotify {
                        writer: &mut writer,
                    },
                );
                table::write_response(&mut writer, &Response { id: Some(id), body })?;
            }
            Event::Reply(response) => writer.send(&response)?,
            Event::Eof => return Ok(()),
            Event::Failed(error) => return Err(error),
        }
    }
    Ok(())
}

/// Serves `reader`/`writer` with `server` until the reader ends. The reader runs on another thread so
/// a `$/cancel` can reach a request that is running.
pub fn serve<R: BufRead + Send, W: Write>(
    reader: R,
    writer: W,
    server: &mut Server<'_>,
) -> Result<(), FrameError> {
    std::thread::scope(|scope| {
        let (sender, receiver) = std::sync::mpsc::channel();
        let cancellation = server.cancellation.clone();
        scope.spawn(move || read_loop(reader, &sender, &cancellation));
        drive(receiver, writer, server)
    })
}

/// Serves the process's stdin and stdout (the `--stdio` mode), until stdin ends.
pub fn serve_stdio(
    sources: Sources<'_>,
    settings: Settings,
    stdout: &mut dyn Write,
) -> Result<(), FrameError> {
    let mut server = Server::live(sources, settings);
    // Pay the inventory enumeration before the first request, so `programs.list` leaves in one batch
    // right after it arrives (the 50 ms rule) instead of after 1+ s of registry and file reads.
    server.warm();
    std::thread::scope(|scope| {
        let (sender, receiver) = std::sync::mpsc::channel();
        let cancellation = server.cancellation.clone();
        scope.spawn(move || {
            let stdin = std::io::stdin();
            read_loop(stdin.lock(), &sender, &cancellation);
        });
        drive(receiver, stdout, &mut server)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cancellable_request_stops_and_a_non_cancellable_one_does_not() {
        let cancel = Cancellation::default();
        cancel.seen(RequestId(1), true);
        cancel.cancel(RequestId(1));
        cancel.begin(RequestId(1), true);
        assert!(cancel.cancelled());
        cancel.end(RequestId(1));

        cancel.seen(RequestId(2), false);
        cancel.cancel(RequestId(2));
        cancel.begin(RequestId(2), false);
        assert!(!cancel.cancelled());
        cancel.end(RequestId(2));

        cancel.begin(RequestId(3), true);
        cancel.cancel(RequestId(3));
        assert!(cancel.cancelled());
        cancel.end(RequestId(3));
        assert!(!cancel.cancelled());
    }
}
