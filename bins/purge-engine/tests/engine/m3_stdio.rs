//! `--stdio` integration tests: the method stream over NDJSON with fixture sources (M3-STDIO).
//!
//! The transport is the same code `--stdio` uses (`purge_engine::stdio::serve`): requests in, one
//! response and any notifications out, on byte streams. No real process is started and nothing outside
//! the test's scratch directory is written.

use std::io::{Read, Write};
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::time::Instant;

use purge_engine::pipeline::{self, Settings, Sources};
use purge_engine::stdio::{Server, serve};
use purge_model::exec::op::Sha256Hex;
use purge_model::exec::session::{
    Expiry, SessionId, SessionIndex, SessionState, SessionSummary, VolumeUsage,
};
use purge_model::{FileTime, ProgramId, View};
use purge_source::fixture::Fixture;
use purge_source::types::{PackageInfo, PackageSignatureKind, RegData};
use serde_json::{Value, json};
use windows_sys::Win32::System::Pipes::CreatePipe;

const UNINSTALL: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
const SID: &str = "S-1-5-21-1000000000-2000000000-3000000000-1001";
const MSI_CODE: &str = "{11111111-2222-3333-4444-555555555555}";
const BURN_CODE: &str = "{66666666-7777-8888-9999-AAAAAAAAAAAA}";
const APPX_ROOT: &str = r"C:\Program Files\WindowsApps\Vendor.App_1.0.0.0_x64__abc";

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("stdio-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One machine with an ordinary entry, an MSI product, a Burn bundle and an AppX entry.
fn machine() -> Fixture {
    let mut fx = Fixture::builder()
        .os("Professional", 26340, 9882)
        .user_sid(SID)
        .elevated(false)
        .build();

    let alpha = format!(r"{UNINSTALL}\Alpha");
    fx.set_value(&alpha, "DisplayName", RegData::from_sz("Alpha App"));
    fx.set_value(&alpha, "Publisher", RegData::from_sz("Alpha Ltd"));
    fx.set_value(&alpha, "DisplayVersion", RegData::from_sz("1.2.3"));
    fx.set_value(
        &alpha,
        "InstallLocation",
        RegData::from_sz(r"C:\Apps\Alpha"),
    );
    fx.set_value(
        &alpha,
        "UninstallString",
        RegData::from_sz(r#""C:\Apps\Alpha\uninst.exe""#),
    );
    fx.add_dir(r"C:\Apps\Alpha");
    fx.add_file(r"C:\Apps\Alpha\alpha.exe", 100);
    fx.add_file(r"C:\Apps\Alpha\data.bin", 200);

    let beta = format!(r"{UNINSTALL}\Beta");
    fx.set_value(&beta, "DisplayName", RegData::from_sz("Beta App"));
    fx.set_value(&beta, "InstallLocation", RegData::from_sz(r"C:\Apps\Beta"));
    fx.set_value(&beta, "SystemComponent", RegData::from_dword(1));
    fx.set_value(&beta, "ParentKeyName", RegData::from_sz("Alpha"));

    let msi = format!(r"{UNINSTALL}\{MSI_CODE}");
    fx.set_value(&msi, "DisplayName", RegData::from_sz("Msi App"));
    fx.set_value(&msi, "WindowsInstaller", RegData::from_dword(1));
    fx.set_value(
        &msi,
        "UninstallString",
        RegData::from_expand_sz(&format!("MsiExec.exe /X{MSI_CODE}")),
    );

    let burn = format!(r"{UNINSTALL}\{BURN_CODE}");
    fx.set_value(&burn, "DisplayName", RegData::from_sz("Burn App"));
    fx.set_value(&burn, "BundleProviderKey", RegData::from_sz("{provider}"));
    fx.set_value(
        &burn,
        "UninstallString",
        RegData::from_sz(r#""C:\ProgramData\Package Cache\bundle.exe" /uninstall"#),
    );

    let appx = format!(r"{UNINSTALL}\Vendor.App");
    fx.set_value(&appx, "DisplayName", RegData::from_sz("Appx App"));
    fx.set_value(&appx, "InstallLocation", RegData::from_sz(APPX_ROOT));
    fx.add_package(PackageInfo {
        full_name: "Vendor.App_1.0.0.0_x64__abc".into(),
        family: "Vendor.App_abc".into(),
        install_location: Some(APPX_ROOT.into()),
        external_location: None,
        sparse: false,
        users: vec![SID.into()],
        is_framework: false,
        is_resource: false,
        signature_kind: PackageSignatureKind::Store,
    });
    fx
}

fn settings(store: &Path) -> Settings {
    Settings {
        data_root: Some(store.to_path_buf()),
        ..Settings::default()
    }
}

/// Runs `requests` through the server and returns the JSON lines it wrote.
fn run_requests(
    fx: &Fixture,
    local: Option<&Path>,
    store: &Path,
    requests: &[Value],
) -> (Vec<Value>, std::time::Duration) {
    let input: String = requests
        .iter()
        .map(|request| format!("{request}\n"))
        .collect();
    let started = Instant::now();
    let mut writer = Stamp::default();
    let mut server = Server::new(
        Sources::of(fx),
        settings(store),
        local.map(Path::to_path_buf),
    );
    serve(
        std::io::Cursor::new(input.into_bytes()),
        &mut writer,
        &mut server,
    )
    .unwrap();
    let first = writer.first.expect("the server wrote nothing");
    let text = String::from_utf8(writer.bytes).unwrap();
    let lines = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (lines, first.duration_since(started))
}

#[derive(Default)]
struct Stamp {
    bytes: Vec<u8>,
    first: Option<Instant>,
}

impl Write for Stamp {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.first.is_none() && !buf.is_empty() {
            self.first = Some(Instant::now());
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn request_methods(lines: &[Value]) -> Vec<&str> {
    lines
        .iter()
        .filter(|line| line.get("id").is_none())
        .filter_map(|line| line["method"].as_str())
        .collect()
}

fn response(lines: &[Value], id: u64) -> &Value {
    lines
        .iter()
        .find(|line| line["id"] == json!(id))
        .unwrap_or_else(|| panic!("no response {id} in {lines:#?}"))
}

/// An anonymous pipe: the read end and the write end as files.
fn os_pipe() -> (std::fs::File, std::fs::File) {
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    // SAFETY: both out-pointers are valid; a null security descriptor and size 0 are the defaults.
    let ok = unsafe { CreatePipe(&mut read, &mut write, std::ptr::null_mut(), 0) };
    assert_ne!(ok, 0, "CreatePipe failed");
    // SAFETY: CreatePipe returned two owned handles; each File owns one from here.
    unsafe {
        (
            std::fs::File::from_raw_handle(read as _),
            std::fs::File::from_raw_handle(write as _),
        )
    }
}

/// The ids of the expected inventory, in the order `pipeline::inventory` lists them.
fn expected_ids(fx: &Fixture) -> Vec<String> {
    pipeline::inventory(Sources::of(fx))
        .doc
        .entries
        .iter()
        .map(|entry| entry.program_id.to_string())
        .collect()
}

#[test]
fn programs_list_sends_raw_rows_first_then_patches() {
    let fx = machine();
    let store = scratch("list-store");
    let local = scratch("list-local");
    let (lines, first_batch) = run_requests(
        &fx,
        Some(&local),
        &store,
        &[json!({"jsonrpc": "2.0", "id": 1, "method": "programs.list"})],
    );

    // The first line is the raw ARP batch. The 50 ms rule is a latency target measured by
    // `xtask bench-launch` on a quiet host; under `cargo test` the machine may be compiling, so this
    // only guards against a stall (a batch held back behind the AppX patches would take seconds).
    assert_eq!(lines[0]["method"], "programs.batch");
    assert!(
        first_batch.as_millis() < 1_000,
        "the first batch took {first_batch:?}"
    );
    // The reply comes after every raw batch and before every patch: the UI paints from it, so the
    // slow AppX-backed patches must not hold it back.
    let reply_at = lines
        .iter()
        .position(|line| line["id"] == json!(1))
        .expect("no programs.list reply");
    assert!(
        lines[..reply_at]
            .iter()
            .all(|line| line["method"] == "programs.batch"),
        "the reply must follow the raw batches: {lines:#?}"
    );
    let first_patch = lines
        .iter()
        .position(|line| line["method"] == "programs.patch")
        .expect("no programs.patch");
    assert!(
        first_patch > reply_at,
        "a patch arrived before the list reply: {lines:#?}"
    );
    assert!(
        lines[reply_at + 1..]
            .iter()
            .all(|line| line["method"] == "programs.patch"),
        "only patches may follow the list reply: {lines:#?}"
    );
    let methods = request_methods(&lines);
    assert_eq!(methods.first(), Some(&"programs.batch"));
    assert_eq!(methods.last(), Some(&"programs.patch"));

    let rows: Vec<&Value> = lines
        .iter()
        .filter(|line| line["method"] == "programs.batch")
        .flat_map(|line| line["params"]["rows"].as_array().unwrap())
        .collect();
    let ids: Vec<String> = rows
        .iter()
        .map(|row| row["program_id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids, expected_ids(&fx));
    assert_eq!(rows.len(), 5);

    let patches: Vec<&Value> = lines
        .iter()
        .filter(|line| line["method"] == "programs.patch")
        .flat_map(|line| line["params"]["patches"].as_array().unwrap())
        .collect();
    let patch = |key: &str| {
        patches
            .iter()
            .find(|patch| patch["program_id"] == json!(format!("HKLM|64|{key}")))
            .unwrap_or_else(|| panic!("no patch for {key}: {patches:#?}"))
    };
    let msi = patch(MSI_CODE);
    assert_eq!(msi["installer"], "Msi");
    assert_eq!(msi["product_code"], MSI_CODE);
    let burn = patch(BURN_CODE);
    assert_eq!(burn["installer"], "Burn");
    assert_eq!(burn["bundle"], format!("HKLM|64|{BURN_CODE}"));
    let appx = patch("Vendor.App");
    assert_eq!(appx["appx"], true);
    let beta = patch("Beta");
    assert_eq!(beta["system_component"], true);
    assert_eq!(beta["parent_key"], "Alpha");
    assert!(patch("Alpha").get("system_component").is_none());
    assert!(patch("Alpha").get("unnamed").is_none());

    let response = response(&lines, 1);
    assert_eq!(response["result"]["count"], 5);
    assert!(response.get("error").is_none());

    // The list is stored under the local data directory for inventory.changes.
    let stored = std::fs::read_to_string(local.join("inventory.json")).unwrap();
    let stored: Value = serde_json::from_str(&stored).unwrap();
    assert_eq!(stored["schema"], "purge.inventory-list/1");
    assert_eq!(stored["programs"].as_array().unwrap().len(), 5);
}

#[test]
fn programs_get_and_sizes_read_the_same_inventory() {
    let fx = machine();
    let store = scratch("get-store");
    let (lines, _) = run_requests(
        &fx,
        None,
        &store,
        &[
            json!({"jsonrpc": "2.0", "id": 1, "method": "programs.get",
                   "params": {"program_id": "HKLM|64|Alpha"}}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "programs.sizes",
                   "params": {"program_ids": ["HKLM|64|Alpha"]}}),
        ],
    );
    let get = response(&lines, 1);
    assert_eq!(get["result"]["name"], "Alpha App");
    assert!(get["result"]["installer"].is_string());
    assert_eq!(
        get["result"]["uninstall_command"],
        r#""C:\Apps\Alpha\uninst.exe""#
    );

    let ready = lines
        .iter()
        .find(|line| line["method"] == "size.ready")
        .expect("no size.ready");
    assert_eq!(ready["params"]["request"], 2);
    assert_eq!(ready["params"]["sizes"][0]["bytes"], 300);
    assert_eq!(response(&lines, 2)["result"]["count"], 1);

    let gone = run_requests(
        &fx,
        None,
        &store,
        &[json!({"jsonrpc": "2.0", "id": 3, "method": "programs.get",
                 "params": {"program_id": "HKLM|64|NoSuch"}})],
    )
    .0;
    assert_eq!(response(&gone, 3)["error"]["data"]["kind"], "gone");
}

#[test]
fn programs_icons_and_uninstall_route_answer_from_the_inventory() {
    let fx = machine();
    let store = scratch("icons-route-store");
    let (lines, _) = run_requests(
        &fx,
        None,
        &store,
        &[
            json!({"jsonrpc": "2.0", "id": 4, "method": "programs.icons",
                   "params": {"program_ids": ["HKLM|64|Alpha", "HKLM|64|Beta"], "px": 24}}),
            json!({"jsonrpc": "2.0", "id": 5, "method": "uninstall.route",
                   "params": {"program_id": "HKLM|64|Alpha"}}),
        ],
    );

    // Two `icon.batch` lines are not needed at 32 per line: one batch carries both programs.
    let batch = lines
        .iter()
        .find(|line| line["method"] == "icon.batch")
        .expect("no icon.batch");
    assert_eq!(batch["params"]["request"], 4);
    let icons = batch["params"]["icons"].as_array().unwrap();
    let ids: Vec<&str> = icons
        .iter()
        .map(|icon| icon["program_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["HKLM|64|Alpha", "HKLM|64|Beta"]);
    assert!(icons.iter().all(|icon| icon["px"] == 24));
    assert_eq!(response(&lines, 4)["result"]["count"], 2);

    // Alpha is machine-scope under C:\Apps, which the default fixture roots leave user-writable.
    let route = &response(&lines, 5)["result"];
    assert_eq!(route["route"], "medium");
    assert_eq!(route["command"], r"C:\Apps\Alpha\uninst.exe");
}

#[test]
fn inventory_changes_compares_with_the_stored_list() {
    let fx = machine();
    let store = scratch("changes-store");
    let local = scratch("changes-local");
    let gone = ProgramId::machine(View::K64, "Gone").unwrap();
    let alpha = ProgramId::machine(View::K64, "Alpha").unwrap();
    let list = json!({
        "schema": "purge.inventory-list/1",
        "programs": [
            {"program_id": gone.to_string(), "name": "Gone App"},
            {"program_id": alpha.to_string(), "name": "Alpha App"},
        ],
    });
    std::fs::write(local.join("inventory.json"), list.to_string()).unwrap();

    let (lines, _) = run_requests(
        &fx,
        Some(&local),
        &store,
        &[json!({"jsonrpc": "2.0", "id": 1, "method": "inventory.changes"})],
    );
    let result = &response(&lines, 1)["result"];
    let disappeared: Vec<&str> = result["disappeared"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["program_id"].as_str().unwrap())
        .collect();
    assert_eq!(disappeared, [gone.to_string()]);
    let appeared: Vec<&str> = result["appeared"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["program_id"].as_str().unwrap())
        .collect();
    assert!(!appeared.contains(&alpha.to_string().as_str()));
    assert!(appeared.contains(&format!("HKLM|64|{MSI_CODE}").as_str()));
    assert_eq!(appeared.len(), 4);

    // After a list wrote the stored file, the same machine shows no change.
    let (lines, _) = run_requests(
        &fx,
        Some(&local),
        &store,
        &[
            json!({"jsonrpc": "2.0", "id": 1, "method": "programs.list"}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "inventory.changes"}),
        ],
    );
    let result = &response(&lines, 2)["result"];
    assert!(result["disappeared"].as_array().unwrap().is_empty());
    assert!(result["appeared"].as_array().unwrap().is_empty());
}

#[test]
fn history_index_reads_sessions_and_the_cap_per_volume() {
    let fx = machine();
    let store = scratch("history-store");
    let sessions = store.join("sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    let root = store.to_string_lossy().into_owned();
    let mut index = SessionIndex::default();
    for (n, bytes) in [(0u64, 1_000u64), (1, 2_000)] {
        let started = FileTime::from_unix_secs(1_794_737_702 + n as i64);
        index.upsert(SessionSummary {
            id: SessionId::new(started, n),
            app: format!("app-{n}"),
            owner: None,
            plan_hash: Sha256Hex([n as u8; 32]),
            state: SessionState::Committed,
            started,
            finished: Some(started),
            counts: Default::default(),
            undone: 0,
            backup_bytes: bytes,
            usage: vec![VolumeUsage {
                serial: 0xC0FF_EE00_1234_5678,
                root: root.clone(),
                bytes,
            }],
            expires: Expiry::from_start(started),
            purged: Vec::new(),
            pending_reboot: false,
            journal: None,
        });
    }
    std::fs::write(
        sessions.join("index.json"),
        serde_json::to_string(&index).unwrap(),
    )
    .unwrap();

    let (lines, _) = run_requests(
        &fx,
        None,
        &store,
        &[json!({"jsonrpc": "2.0", "id": 1, "method": "history.index"})],
    );
    let result = &response(&lines, 1)["result"];
    let listed: Vec<&str> = result["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["app"].as_str().unwrap())
        .collect();
    // Newest first, though the index is ordered oldest first.
    assert_eq!(listed, ["app-1", "app-0"]);
    let volume = &result["volumes"][0];
    assert_eq!(volume["serial"], 0xC0FF_EE00_1234_5678u64);
    assert_eq!(volume["used"], 3_000);
    let cap = volume["cap"].as_u64().unwrap();
    assert!(cap > 0 && cap <= 10 * (1 << 30), "cap {cap}");
}

#[test]
fn engine_hello_is_the_medium_hello() {
    let fx = machine();
    let store = scratch("hello-store");
    let (lines, _) = run_requests(
        &fx,
        None,
        &store,
        &[json!({"jsonrpc": "2.0", "id": 1, "method": "engine.hello"})],
    );
    let result = &response(&lines, 1)["result"];
    assert_eq!(result["version"], env!("CARGO_PKG_VERSION"));
    assert!(result["elevation_type"].is_string());
    assert!(result["shell_matches"].is_boolean());
    assert!(result.get("baseline_trust").is_some());
}

#[test]
fn cancel_is_accepted_and_never_answers() {
    let fx = machine();
    let store = scratch("cancel-store");
    let (lines, _) = run_requests(
        &fx,
        None,
        &store,
        &[
            json!({"jsonrpc": "2.0", "id": 1, "method": "programs.list"}),
            json!({"jsonrpc": "2.0", "method": "$/cancel", "params": {"request": 1}}),
            // A non-cancellable method's cancel is refused: no answer, no effect.
            json!({"jsonrpc": "2.0", "method": "$/cancel", "params": {"request": 99}}),
        ],
    );
    assert_eq!(
        lines.iter().filter(|line| line.get("id").is_some()).count(),
        1
    );
    let response = response(&lines, 1);
    assert!(response.get("error").is_none(), "{response:#?}");
    // The list either finished before the cancel or stopped at a batch boundary; both are valid.
    let count = response["result"]["count"].as_u64().unwrap();
    assert!(count <= 5, "{response:#?}");
}

#[test]
fn the_same_stream_over_anonymous_pipes() {
    let fx = machine();
    let store = scratch("pipe-store");
    let (input_read, mut input_write) = os_pipe();
    let (output_read, output_write) = os_pipe();
    std::thread::scope(|scope| {
        let mut server = Server::new(Sources::of(&fx), settings(&store), None);
        let server = scope.spawn(move || {
            serve(
                std::io::BufReader::new(input_read),
                output_write,
                &mut server,
            )
        });

        let requests = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"programs.list\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"programs.get\",",
            "\"params\":{\"program_id\":\"HKLM|64|Alpha\"}}\n",
        );
        input_write.write_all(requests.as_bytes()).unwrap();
        drop(input_write);

        let mut text = String::new();
        std::io::BufReader::new(output_read)
            .read_to_string(&mut text)
            .unwrap();
        server.join().unwrap().unwrap();

        let lines: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines[0]["method"], "programs.batch");
        // The reply is written before the patches of the same request.
        let reply_at = lines
            .iter()
            .position(|line| line["id"] == json!(1))
            .unwrap();
        let first_patch = lines
            .iter()
            .position(|line| line["method"] == "programs.patch")
            .unwrap();
        assert!(first_patch > reply_at, "{lines:#?}");
        assert_eq!(response(&lines, 2)["result"]["name"], "Alpha App");
        assert_eq!(response(&lines, 1)["result"]["count"], 5);
    });
}
