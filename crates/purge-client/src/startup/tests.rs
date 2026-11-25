//! The start of the app: the engine, or the fallback notice and the sample data when it is missing or
//! failing (port of `EngineLinkTests.cs`).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::testing::{
    Events, Peer, ScriptedEngine, events, fixture, healthy, hello_result, id_of, method_of,
    patch_params,
};

fn run_startup(startup: Startup) -> (StartupResult, Events) {
    let (sink, mut events) = events();
    startup.start(sink);
    assert!(events.seen.is_empty());
    let result = events.startup();
    assert!(
        events.seen.is_empty(),
        "nothing of the engine before its Startup"
    );
    (result, events)
}

/// A startup whose engine is scripted by `on_line`.
fn scripted(on_line: impl Fn(&str, &Peer) + Send + 'static) -> Startup {
    Startup::with_open(Box::new(move |sink| {
        let (client, _peer) = ScriptedEngine::with_sink(on_line, sink);
        Ok(client as Arc<dyn Engine>)
    }))
}

#[test]
fn an_engine_that_answers_is_used_without_a_notice() {
    let marks = Arc::new(Mutex::new(Vec::new()));
    let (m1, m2) = (marks.clone(), marks.clone());
    let startup = scripted(healthy)
        .on_engine_ready(Box::new(move || m1.lock().unwrap().push("engine_ready")))
        .on_list_reply(Box::new(move || m2.lock().unwrap().push("list_reply")));
    let (result, mut events) = run_startup(startup);
    assert_eq!(result.error, None);
    assert!(result.engine.is_live());
    assert_eq!(result.hello.hello.version, "0.1.0");
    assert_eq!(result.list.rows.len(), 1);
    assert_eq!(result.list.rows[0].name, "Git");
    assert_eq!(*marks.lock().unwrap(), ["engine_ready", "list_reply"]);
    // The changes reply, held during the start, follows the Startup.
    let Ok(Answer::InventoryChanges(changes)) = events.reply(result.changes) else {
        panic!()
    };
    let expected: purge_rpc::methods::InventoryChanges =
        serde_json::from_str(&fixture("stdio.inventory.changes.result.json")).unwrap();
    assert_eq!(changes, expected);
}

/// The real engine's order: the list reply, its rows, then (after `delay`) its patches.
fn patched_later(delay: Duration) -> impl Fn(&str, &Peer) + Send + 'static {
    move |line, peer| {
        healthy(line, peer);
        if method_of(line) == "programs.list" {
            std::thread::sleep(delay);
            peer.send(&format!(
                r#"{{"jsonrpc":"2.0","method":"programs.patch","params":{}}}"#,
                patch_params(id_of(line))
            ));
        }
    }
}

#[test]
fn the_patches_after_the_list_reply_come_with_the_list() {
    // The engine sends its reply before the patches; a row without its patch reads as a named
    // app, so the list waits for them and the page's first rows are already in their tabs.
    let marks = Arc::new(Mutex::new(Vec::new()));
    let m = marks.clone();
    let startup = scripted(patched_later(Duration::from_millis(60)))
        .on_list_patched(Box::new(move || m.lock().unwrap().push("list_patched")));
    let (result, mut events) = run_startup(startup);
    assert_eq!(result.error, None);
    assert_eq!(result.list.rows.len(), 1);
    let patch = result
        .list
        .patches
        .last()
        .expect("the late patch is in the list");
    assert_eq!(patch.program_id, result.list.rows[0].program_id);
    assert_eq!(*marks.lock().unwrap(), ["list_patched"]);
    // It is not delivered to the page a second time.
    events.drain_for(Duration::from_millis(200));
    assert!(
        !events
            .seen
            .iter()
            .any(|e| matches!(e, ClientEvent::ProgramsPatched(_)))
    );
}

#[test]
fn a_list_whose_patches_are_late_is_handed_over_and_they_follow() {
    let started = Instant::now();
    let (result, mut events) = run_startup(scripted(patched_later(
        PATCH_WAIT + Duration::from_millis(1500),
    )));
    let waited = started.elapsed();
    assert!(result.list.patches.is_empty());
    assert!(waited >= PATCH_WAIT, "{waited:?}");
    assert!(
        waited < PATCH_WAIT + Duration::from_millis(1000),
        "{waited:?}"
    );
    events.drain_for(Duration::from_millis(2000));
    assert!(
        events
            .seen
            .iter()
            .any(|e| matches!(e, ClientEvent::ProgramsPatched(p) if p.len() == 1))
    );
}

#[test]
fn changes_are_asked_before_the_list() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let o = order.clone();
    let startup = scripted(move |line, peer| {
        o.lock().unwrap().push(method_of(line));
        healthy(line, peer);
    });
    let (_result, _events) = run_startup(startup);
    assert_eq!(
        *order.lock().unwrap(),
        ["engine.hello", "inventory.changes", "programs.list"]
    );
}

#[test]
fn a_missing_engine_file_falls_back_to_sample_data_with_a_notice() {
    let path = std::env::temp_dir()
        .join("purge-no-such-engine")
        .join("purge-engine.exe");
    let (result, _events) = run_startup(Startup::engine(path));
    let error = result.error.unwrap();
    assert!(error.starts_with(FALLBACK_NOTICE), "{error}");
    assert!(error.contains("purge-engine.exe"), "{error}");
    assert!(error.ends_with('.'));
    assert!(!result.engine.is_live());
    assert!(!result.list.rows.is_empty());
    assert_eq!(result.hello.hello.version, "0.0.0-stub");
}

#[test]
fn a_file_that_is_not_an_engine_falls_back() {
    let path = std::env::temp_dir().join(format!(
        "purge-not-an-engine-{}-{}.exe",
        std::process::id(),
        purge_win::os::random_u64().unwrap()
    ));
    std::fs::write(&path, "not a program").unwrap();
    let (result, _events) = run_startup(Startup::engine(path.clone()));
    let error = result.error.unwrap();
    assert!(
        error.starts_with(&format!("{FALLBACK_NOTICE}Windows could not start it: ")),
        "{error}"
    );
    assert!(!result.engine.is_live());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn an_engine_that_ends_at_once_falls_back() {
    let (result, mut events) = run_startup(scripted(|_, peer| peer.end()));
    let error = result.error.unwrap();
    assert!(
        error.contains("sample data") && error.contains("ended"),
        "{error}"
    );
    assert!(!result.engine.is_live());
    assert!(!result.list.rows.is_empty());
    // The broken engine is never shown: not even its end.
    events.drain_for(Duration::from_millis(200));
    assert!(
        !events
            .seen
            .iter()
            .any(|e| matches!(e, ClientEvent::EngineClosed { .. }))
    );
}

#[test]
fn an_engine_that_answers_with_an_error_falls_back() {
    let (result, _events) = run_startup(scripted(|line, peer| {
        peer.send(&format!(
            r#"{{"jsonrpc":"2.0","id":{},"error":{}}}"#,
            id_of(line),
            fixture("error.runtime.json")
        ))
    }));
    let error = result.error.unwrap();
    assert!(
        error.contains("the harvest store could not be opened"),
        "{error}"
    );
    assert!(!result.engine.is_live());
}

#[test]
fn an_engine_that_fails_after_hello_falls_back() {
    let (result, _events) = run_startup(scripted(|line, peer| {
        if method_of(line) == "engine.hello" {
            peer.send(&format!(
                r#"{{"jsonrpc":"2.0","id":{},"result":{}}}"#,
                id_of(line),
                hello_result()
            ));
        } else {
            peer.end();
        }
    }));
    assert!(result.error.unwrap().contains("sample data"));
    assert!(!result.engine.is_live());
}

#[test]
fn an_engine_that_does_not_answer_in_time_falls_back() {
    let (result, _events) = run_startup(scripted(|_, _| {}).timeout(Duration::from_millis(300)));
    let error = result.error.unwrap();
    assert!(error.contains("did not answer"), "{error}");
    assert!(!result.engine.is_live());
}

#[test]
fn sample_mode_never_opens_the_engine() {
    let (result, _events) = run_startup(Startup::sample());
    assert_eq!(result.error, None);
    assert!(!result.engine.is_live());
    assert!(!result.list.rows.is_empty());
}

#[test]
fn the_bench_stub_answers_through_the_gate() {
    let (result, _events) = run_startup(Startup::sample().bench_rows(500));
    assert_eq!(result.list.rows.len(), 500);
}
