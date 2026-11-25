//! The History and Quarantine pages on the link: each page reads its list when shown, the sample
//! answers the reads and refuses every change without starting a broker, an idle page gives its
//! broker back, and a page's broker calls go to its session (a fake broker over OS pipes; no
//! broker is ever launched here).

use std::io::{BufRead, BufReader, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use purge_ui_model::history::HistoryCall;
use purge_ui_model::history::text as htext;

use super::*;
use crate::link::Source;
use crate::model::Programs;
use crate::model::tests::{clock, sample_programs};
use crate::prefs::Prefs;

/// A link on the sample engine, started, and a model on it.
fn started() -> (Link, Model) {
    let mut link = Link::new(|| {});
    let mut model = Model::new(Prefs::default(), sample_programs(), true);
    model.programs = Programs::new(clock(), |_| false);
    link.start(&Source::Sample { bench_rows: 0 });
    let t0 = Instant::now();
    while !link.started && t0.elapsed().as_secs() < 10 {
        link.pump(&mut model);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(link.started);
    (link, model)
}

/// Pumps until `done`, for ten seconds at most.
fn until(link: &mut Link, model: &mut Model, done: impl Fn(&Model) -> bool) {
    let t0 = Instant::now();
    while !done(model) && t0.elapsed().as_secs() < 10 {
        link.pump(model);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(done(model), "timed out");
}

#[test]
fn a_page_reads_its_list_when_it_is_shown() {
    let (mut link, mut model) = started();
    assert!(model.history.page.sessions().is_empty(), "not read before");
    model.page = Page::History;
    until(&mut link, &mut model, |m| {
        m.history.page.sessions().len() == 8
    });
    model.page = Page::Quarantine;
    until(&mut link, &mut model, |m| {
        m.quarantine.page.batches().len() == 6
    });
    assert!(model.quarantine.selected.is_some(), "the first is selected");
    assert_eq!(model.quarantine.page.volumes().len(), 2);
}

#[test]
fn the_sample_reads_but_refuses_every_change_and_starts_no_broker() {
    let (mut link, mut model) = started();
    model.page = Page::History;
    until(&mut link, &mut model, |m| {
        !m.history.page.sessions().is_empty()
    });
    let h = &mut model.history;
    let ccleaner = h
        .page
        .sessions()
        .iter()
        .find(|s| s.name == "CCleaner")
        .map(|s| s.id.clone())
        .expect("the sample's CCleaner");
    h.page.select(&ccleaner);
    let r = h.page.show_items();
    h.take(r);
    link.pump(&mut model);
    let items = model.history.page.items().expect("read from the sample");
    assert_eq!(items.len(), 4);
    let op = items[0].op;
    model.history.page.set_checked(op, true);
    let r = model.history.page.restore(false);
    model.history.take(r);
    link.pump(&mut model);
    let error = model.history.page.action_error().unwrap_or_default();
    assert!(error.contains(NOT_LIVE), "{error}");
    assert!(!model.history.page.busy());

    model.page = Page::Quarantine;
    until(&mut link, &mut model, |m| {
        !m.quarantine.page.batches().is_empty()
    });
    let q = &mut model.quarantine;
    let id = q.selected.clone().expect("a cleanup");
    let r = q.page.delete_now(&id, true);
    q.take(r);
    link.pump(&mut model);
    let error = model.quarantine.page.action_error().unwrap_or_default();
    assert!(error.contains(NOT_LIVE), "{error}");
    let r = model.quarantine.page.review_expired();
    model.quarantine.take(r);
    link.pump(&mut model);
    let error = model.quarantine.page.action_error().unwrap_or_default();
    assert!(error.contains(NOT_LIVE), "{error}");
    assert_eq!(model.quarantine.page.batches().len(), 6, "nothing deleted");

    assert!(link.broker.launching.is_none() && link.broker.session.is_none());
}

#[test]
fn leaving_a_page_while_idle_gives_its_broker_back() {
    let (mut link, mut model) = started();
    model.page = Page::History;
    until(&mut link, &mut model, |m| {
        !m.history.page.sessions().is_empty()
    });
    let r = model.history.page.show_items();
    model.history.take(r);
    link.pump(&mut model);
    assert!(model.history.page.broker_is_live(), "the sample's broker");
    model.page = Page::Settings;
    link.pump(&mut model);
    assert!(!model.history.page.broker_is_live(), "given back");
}

fn fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/purge-rpc/fixtures")
        .join(name);
    let text = std::fs::read_to_string(&path).expect("the fixture");
    // One line: no string in these fixtures holds a line break.
    text.replace(['\r', '\n'], " ")
}

/// The text after `"key":` in a request line, up to the next `,` or `}` (quotes removed).
fn field<'a>(line: &'a str, key: &str) -> &'a str {
    let at = format!("\"{key}\":");
    line.split_once(&at)
        .map(|(_, rest)| rest.split([',', '}']).next().unwrap_or_default())
        .unwrap_or_default()
        .trim()
        .trim_matches('"')
}

/// A broker played by the test over two OS pipes: it answers `engine.hello`, `history.get` and
/// `undo.run` from purge-rpc's fixtures, and records the methods it was asked for.
fn fake_broker(sink: purge_client::Sink) -> (Arc<BrokerClient>, Arc<Mutex<Vec<String>>>) {
    let (from_ui, to_broker) = std::io::pipe().expect("a pipe");
    let (from_broker, to_ui) = std::io::pipe().expect("a pipe");
    let asked = Arc::new(Mutex::new(Vec::new()));
    let log = asked.clone();
    std::thread::spawn(move || {
        let mut out = to_ui;
        for line in BufReader::new(from_ui).lines() {
            let Ok(line) = line else { break };
            let method = field(&line, "method").to_owned();
            let Ok(id) = field(&line, "id").parse::<u64>() else {
                continue;
            };
            let result = match method.as_str() {
                "engine.hello" => fixture("pipe.engine.hello.result.json"),
                "history.get" => fixture("pipe.history.get.result.json"),
                "undo.run" => fixture("pipe.undo.run.result.json"),
                "broker.shutdown" => r#"{"exiting":true}"#.into(),
                _ => continue,
            };
            log.lock().unwrap().push(method);
            let reply = format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#);
            if writeln!(out, "{reply}").and_then(|_| out.flush()).is_err() {
                break;
            }
        }
    });
    let client = BrokerClient::over(
        Box::new(to_broker),
        Box::new(from_broker),
        Box::new(|| {}),
        sink,
        Duration::from_secs(10),
    )
    .expect("the fake broker's session");
    (client, asked)
}

#[test]
fn the_history_pages_broker_calls_go_to_its_session_and_their_answers_come_back() {
    let (mut link, mut model) = started();
    model.page = Page::History;
    until(&mut link, &mut model, |m| {
        !m.history.page.sessions().is_empty()
    });
    // As if the page's launch had ended with this session; no broker is ever started here.
    link.live = true;
    let (client, asked) = fake_broker(link.sink.clone());
    link.broker.session = Some((Owner::History, client));
    let h = &mut model.history;
    let r = h.page.show_items();
    assert_eq!(r, vec![HistoryCall::Launch { read_only: true }]);
    let r = h.page.on_launch(BrokerLaunch::started());
    h.take(r);
    until(&mut link, &mut model, |m| m.history.page.items().is_some());
    let items = model.history.page.items().unwrap_or_default();
    assert_eq!(items.len(), 1, "the fixture's one item");
    let op = items[0].op;
    model.history.page.set_checked(op, true);
    let r = model.history.page.restore(false);
    model.history.take(r);
    until(&mut link, &mut model, |m| {
        m.history.page.restore_title().is_some()
    });
    assert_eq!(
        model.history.page.restore_title(),
        Some(htext::PUT_BACK_WITH_CONFLICTS)
    );
    let asked = asked.lock().unwrap().clone();
    assert!(asked.contains(&"history.get".to_string()), "{asked:?}");
    assert!(asked.contains(&"undo.run".to_string()), "{asked:?}");
    assert!(link.broker.launching.is_none(), "nothing was launched");
    assert!(
        model.quarantine.page.batches().is_empty(),
        "Quarantine untouched"
    );
}
