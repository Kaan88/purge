//! The stdio client against an engine played by the test, and against a real child process (ports of
//! `StdioEngineClientTests.cs` and the engine half of `UninstallClientTests.cs`).

use std::time::Duration;

use purge_model::ProgramId;
use purge_rpc::methods::{
    NoParams, NonEmpty, ProgramParams, ProgramsParams, RunUserParams, StdioCall,
};
use serde_json::Value;

use super::*;
use crate::testing::{
    LIMIT, ScriptedEngine, batch_params, fixture, hello_result, id_of, method_of, patch_params,
};

fn git() -> ProgramId {
    "HKLM|64|Git_is1".parse().unwrap()
}

fn list() -> StdioCall {
    StdioCall::ProgramsList(NoParams {})
}

fn hello() -> StdioCall {
    StdioCall::EngineHello(NoParams {})
}

fn result(id: u64, result: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#)
}

fn notify(method: &str, params: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","method":"{method}","params":{params}}}"#)
}

#[test]
fn hello_and_list_follow_the_wire_format() {
    let mut e = ScriptedEngine::healthy();
    let call = e.client.request(hello());
    let Ok(Answer::MediumHello(h)) = e.events.reply(call) else {
        panic!()
    };
    assert_eq!(h.hello.version, "0.1.0");
    assert!(!h.hello.elevated);
    assert_eq!(h.hello.edition, "Professional");
    assert_eq!((h.hello.build, h.hello.ubr), (26100, 9711));
    assert_eq!(h.hello.user_sid, "S-1-5-21-1-2-3-1001");
    assert_eq!(h.hello.policy_version, "bl.1");
    assert!(h.hello.baseline.baseline_available);

    let call = e.client.request(list());
    let Ok(Answer::Programs(l)) = e.events.reply(call) else {
        panic!()
    };
    assert_eq!(l.rows.len(), 1);
    let row = &l.rows[0];
    assert_eq!(row.program_id, git());
    assert_eq!(row.name, "Git");
    assert_eq!(row.version.as_deref(), Some("2.47.0"));
    assert_eq!(
        row.publisher.as_deref(),
        Some("The Git Development Community")
    );
    assert_eq!(row.install_time.map(|t| t.0), Some(134076753020000000));

    let requests = e.peer.requests();
    assert_eq!(requests.len(), 2);
    let parsed: Vec<Value> = requests
        .iter()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(parsed.iter().all(|v| v["jsonrpc"] == "2.0"));
    assert_eq!(parsed[0]["method"], "engine.hello");
    assert_eq!(parsed[1]["method"], "programs.list");
    assert_eq!(
        (parsed[0]["id"].as_u64(), parsed[1]["id"].as_u64()),
        (Some(1), Some(2))
    );
    // The C# client always wrote a params object.
    assert_eq!(parsed[0]["params"], serde_json::json!({}));
}

#[test]
fn rows_may_arrive_before_the_reply_that_counts_them() {
    let mut e = ScriptedEngine::new(|line, peer| {
        let id = id_of(line);
        peer.send(&notify("programs.batch", &batch_params(id)));
        peer.send(&result(id, r#"{"count":1}"#));
    });
    let call = e.client.request(list());
    let Ok(Answer::Programs(l)) = e.events.reply(call) else {
        panic!()
    };
    assert_eq!(l.rows.len(), 1);
}

#[test]
fn waits_for_the_rows_the_reply_promised() {
    let mut e = ScriptedEngine::new(|line, peer| peer.send(&result(id_of(line), r#"{"count":1}"#)));
    let call = e.client.request(list());
    assert!(!e.events.replied_within(call, Duration::from_millis(150)));
    e.peer.send(&notify("programs.batch", &batch_params(1)));
    let Ok(Answer::Programs(l)) = e.events.reply(call) else {
        panic!()
    };
    assert_eq!(l.rows.len(), 1);
}

#[test]
fn patches_go_to_the_list_while_it_is_open_and_to_the_page_after() {
    // Before the reply: only in the result. After the reply, while rows are missing: in the result
    // and on the page. After the list ended: on the page.
    let mut e = ScriptedEngine::new(|line, peer| {
        let id = id_of(line);
        peer.send(&notify("programs.patch", &patch_params(id)));
        peer.send(&result(id, r#"{"count":1}"#));
        peer.send(&notify("programs.patch", &patch_params(id)));
        peer.send(&notify("programs.batch", &batch_params(id)));
        peer.send(&notify("programs.patch", &patch_params(id)));
        // Another request's patch is no page's.
        peer.send(&notify("programs.patch", &patch_params(77)));
    });
    let call = e.client.request(list());
    let Ok(Answer::Programs(l)) = e.events.reply(call) else {
        panic!()
    };
    assert_eq!(l.patches.len(), 2);
    e.events.drain_for(Duration::from_millis(200));
    let patched = e
        .events
        .seen
        .iter()
        .filter(|ev| matches!(ev, ClientEvent::ProgramsPatched(p) if p.len() == 1))
        .count();
    assert_eq!(patched, 2);
}

#[test]
fn an_error_response_names_its_kind() {
    let mut e = ScriptedEngine::new(|line, peer| {
        peer.send(&format!(
            r#"{{"jsonrpc":"2.0","id":{},"error":{}}}"#,
            id_of(line),
            fixture("error.runtime.json")
        ))
    });
    let call = e.client.request(hello());
    let Err(ClientError::Rpc(error)) = e.events.reply(call) else {
        panic!()
    };
    assert_eq!(error.kind.as_deref(), Some("runtime"));
    assert_eq!(error.code, -32000);
    assert_eq!(error.message, "the harvest store could not be opened");
}

#[test]
fn an_error_of_a_newer_kind_is_still_an_error_and_keeps_the_link() {
    let mut e = ScriptedEngine::new(|line, peer| {
        let id = id_of(line);
        match method_of(line).as_str() {
            "engine.hello" => peer.send(&format!(
                r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":-32000,"message":"","data":{{"kind":"brand_new","x":1}}}}}}"#
            )),
            _ => peer.send(&result(id, &hello_result())),
        }
    });
    let call = e.client.request(hello());
    let Err(ClientError::Rpc(error)) = e.events.reply(call) else {
        panic!()
    };
    assert_eq!(error.kind.as_deref(), Some("brand_new"));
    assert_eq!(error.message, "The engine reported an error.");
    let call = e.client.request(StdioCall::InventoryChanges(NoParams {}));
    assert!(
        e.events.reply(call).is_err(),
        "a hello is not a changes answer"
    );
    assert!(e.client.closed_reason().is_none());
}

#[test]
fn a_gone_program_is_none() {
    let mut e = ScriptedEngine::new(|line, peer| {
        peer.send(&format!(
            r#"{{"jsonrpc":"2.0","id":{},"error":{}}}"#,
            id_of(line),
            fixture("error.gone.json")
        ))
    });
    let call = e
        .client
        .request(StdioCall::ProgramsGet(ProgramParams { program_id: git() }));
    assert_eq!(e.events.reply(call), Ok(Answer::Program(None)));
}

#[test]
fn sizes_arrive_in_batches_then_the_call_ends() {
    let mut e = ScriptedEngine::new(|line, peer| {
        let id = id_of(line);
        let mut v: Value = serde_json::from_str(&fixture("notification.size.ready.json")).unwrap();
        v["request"] = id.into();
        let n = v["sizes"].as_array().unwrap().len();
        // Two batches promised; the first before the reply.
        peer.send(&notify("size.ready", &v.to_string()));
        peer.send(&result(id, &format!(r#"{{"count":{}}}"#, 2 * n)));
        peer.send(&notify("size.ready", &v.to_string()));
    });
    let ids = NonEmpty::new(vec![git()]).unwrap();
    let call = e.client.request(StdioCall::ProgramsSizes(ProgramsParams {
        program_ids: ids,
    }));
    assert_eq!(e.events.reply(call), Ok(Answer::Done));
    assert!(
        e.events
            .seen
            .iter()
            .any(|ev| matches!(ev, ClientEvent::Sizes { call: c, .. } if *c == call))
    );
}

#[test]
fn an_engine_that_ends_fails_the_open_request() {
    let mut e = ScriptedEngine::new(|_, peer| peer.end());
    let call = e.client.request(hello());
    let Err(ClientError::Link { reason, not_sent }) = e.events.reply(call) else {
        panic!()
    };
    assert!(reason.contains("ended"), "{reason}");
    assert!(!not_sent, "the request went out before the link ended");
    // Later calls fail at once instead of waiting for a reply that cannot come.
    let later = e.client.request(hello());
    let Err(ClientError::Link { not_sent, .. }) = e.events.reply(later) else {
        panic!()
    };
    assert!(not_sent);
    let closed = e.events.find(|ev| match ev {
        ClientEvent::EngineClosed { reason } => Some(reason.clone()),
        _ => None,
    });
    assert_eq!(closed, "The engine ended.");
}

#[test]
fn a_line_that_is_not_json_ends_the_link() {
    let mut e = ScriptedEngine::new(|_, peer| peer.send("this is not json"));
    let call = e.client.request(hello());
    let Err(ClientError::Link { reason, .. }) = e.events.reply(call) else {
        panic!()
    };
    assert!(
        reason.starts_with("The engine sent a line that is not JSON-RPC: "),
        "{reason}"
    );
}

#[test]
fn cancelling_sends_cancel_and_ends_the_call() {
    let mut e = ScriptedEngine::new(|_, _| {});
    let call = e.client.request(list());
    e.peer.wait_requests(1);
    e.client.cancel(call);
    assert_eq!(e.events.reply(call), Err(ClientError::Cancelled));
    let requests = e.peer.wait_requests(2);
    let cancel: Value = serde_json::from_str(&requests[1]).unwrap();
    assert_eq!(cancel["method"], "$/cancel");
    assert_eq!(cancel["params"]["request"], 1);
    assert!(cancel.get("id").is_none());
    assert!(
        e.client.closed_reason().is_none(),
        "cancelling one call keeps the link"
    );
}

#[test]
fn closing_answers_every_open_call_once() {
    let mut e = ScriptedEngine::new(|_, _| {});
    let a = e.client.request(list());
    let b = e.client.request(hello());
    e.client.close();
    for call in [a, b] {
        let Err(ClientError::Link { reason, .. }) = e.events.reply(call) else {
            panic!()
        };
        assert_eq!(reason, "The engine link was closed.");
    }
    e.events.drain_for(Duration::from_millis(100));
    let replies = e
        .events
        .seen
        .iter()
        .filter(|ev| matches!(ev, ClientEvent::Reply { .. }))
        .count();
    assert_eq!(replies, 0, "no second answer");
}

#[test]
fn run_user_sends_quiet_reports_progress_and_returns_the_result() {
    let mut e = ScriptedEngine::new(|line, peer| {
        let id = id_of(line);
        let mut p: Value =
            serde_json::from_str(&fixture("notification.uninstall.progress.json")).unwrap();
        p["request"] = id.into();
        peer.send(&notify("uninstall.progress", &p.to_string()));
        peer.send(&notify("uninstall.progress", &p.to_string()));
        peer.send(&result(
            id,
            &fixture("stdio.uninstall.run_user.result.json"),
        ));
    });
    let call = e.client.request(StdioCall::UninstallRunUser(RunUserParams {
        program_id: git(),
        quiet: true,
    }));
    let Ok(Answer::RunUser(r)) = e.events.reply(call) else {
        panic!()
    };
    let expected: purge_rpc::methods::RunUserResult =
        serde_json::from_str(&fixture("stdio.uninstall.run_user.result.json")).unwrap();
    assert_eq!(r, expected);
    let progress = e
        .events
        .seen
        .iter()
        .filter(|ev| matches!(ev, ClientEvent::Progress { call: c, .. } if *c == call))
        .count();
    assert_eq!(progress, 2);
    let sent: Value = serde_json::from_str(&e.peer.requests()[0]).unwrap();
    assert_eq!(sent["method"], "uninstall.run_user");
    assert_eq!(sent["params"]["quiet"], true);
    assert_eq!(sent["params"]["program_id"], "HKLM|64|Git_is1");
}

#[test]
fn a_wrong_route_refusal_keeps_its_data_and_the_link() {
    let mut e = ScriptedEngine::new(|line, peer| {
        peer.send(&format!(
            r#"{{"jsonrpc":"2.0","id":{},"error":{}}}"#,
            id_of(line),
            fixture("error.wrong_route.json")
        ))
    });
    let call = e.client.request(StdioCall::UninstallRunUser(RunUserParams {
        program_id: git(),
        quiet: false,
    }));
    let Err(ClientError::Rpc(error)) = e.events.reply(call) else {
        panic!()
    };
    assert_eq!(error.kind.as_deref(), Some("wrong_route"));
    assert!(matches!(
        error.data,
        Some(purge_rpc::error::ErrorData::WrongRoute { .. })
    ));
    assert!(e.client.closed_reason().is_none());
}

#[test]
fn a_missing_engine_file_is_reported() {
    let path = std::env::temp_dir()
        .join("purge-no-such-engine")
        .join("purge-engine.exe");
    let (sink, _events) = crate::testing::events();
    let error = EngineClient::start(&path, "--stdio", sink).unwrap_err();
    assert!(matches!(&error, StartError::NotFound(p) if p.contains("purge-engine.exe")));
    assert!(
        error
            .to_string()
            .starts_with("The engine was not found at ")
    );
}

#[test]
fn a_child_process_talks_over_inherited_pipes_and_dies_with_its_job() {
    let dir = std::env::temp_dir().join(format!(
        "purge-client-stdio-{}-{}",
        std::process::id(),
        purge_win::os::random_u64().unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let pid_file = dir.join("pid.txt");
    let script = dir.join("engine.ps1");
    // A stand-in engine: writes its pid, answers hello and programs.list from stdin to stdout.
    let body = format!(
        r#"[IO.File]::WriteAllText('{pid}', [string]$PID)
$out = [Console]::Out
while ($true) {{
  $l = [Console]::In.ReadLine()
  if ($null -eq $l) {{ break }}
  $id = [regex]::Match($l, '"id":(\d+)').Groups[1].Value
  if ($l -match 'engine.hello') {{
    $out.WriteLine('{{"jsonrpc":"2.0","id":' + $id + ',"result":{hello}}}')
  }} elseif ($l -match 'programs.list') {{
    $out.WriteLine('{{"jsonrpc":"2.0","id":' + $id + ',"result":{{"count":1}}}}')
    $p = '{batch}'.Replace('"request":0', '"request":' + $id)
    $out.WriteLine('{{"jsonrpc":"2.0","method":"programs.batch","params":' + $p + '}}')
  }}
  $out.Flush()
}}
"#,
        pid = pid_file.display(),
        hello = hello_result(),
        batch = batch_params(0),
    );
    std::fs::write(&script, body).unwrap();
    let powershell = purge_win::known_folders::system_windows_dir()
        .unwrap()
        .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let (sink, mut events) = crate::testing::events();
    let client = EngineClient::start(
        &powershell,
        &format!(
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{}\"",
            script.display()
        ),
        sink,
    )
    .unwrap();
    let call = client.request(hello());
    // PowerShell can be slow to start on a cold machine.
    let answer = events.find(|ev| match ev {
        ClientEvent::Reply { call: c, result } if *c == call => Some(result.clone()),
        _ => None,
    });
    let Ok(Answer::MediumHello(h)) = answer else {
        panic!("{answer:?}")
    };
    assert_eq!(h.hello.version, "0.1.0");
    let call = client.request(list());
    let Ok(Answer::Programs(l)) = events.reply(call) else {
        panic!()
    };
    assert_eq!(l.rows.len(), 1);
    let pid: u32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let process = purge_win::process::ProcessHandle::open(pid).unwrap();
    client.close();
    drop(client);
    assert!(
        process.wait_exit(Some(LIMIT)).unwrap(),
        "closing the client must end the engine through its kill-on-close job"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
