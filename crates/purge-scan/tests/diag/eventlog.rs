//! REG-DIAG: event-log sources whose message files are the app's.

use purge_model::{Action, Band, Candidate, Category, EvidenceKind, ManifestKind, Target, Tier};
use purge_source::types::RegData;

use super::world::*;

/// The candidates REG-DIAG finds under `EventLog`.
fn sources(world: &World) -> Vec<Candidate> {
    world
        .diag()
        .into_iter()
        .filter(|c| matches!(&c.target, Target::RegKey { path } if path.to_ascii_lowercase().contains(r"\eventlog")))
        .collect()
}

#[test]
fn eventlog_source_message_file_in_root_likely() {
    let mut fx = machine();
    event_source(&mut fx, "Application", "App Service", &app_file("msg.dll"));
    let world = World::new(fx).ready();
    let found = sources(&world);
    assert_eq!(found.len(), 1, "{:#?}", spots(&found));
    let c = get(&found, &source_key("Application", "App Service"));
    assert_eq!(c.action, Action::DeleteKey);
    assert_eq!(c.category, Category::Registration);
    assert!(c.blockers.is_empty(), "{:?}", c.blockers);
    assert!(
        has(c, EvidenceKind::ChainedRef, Tier::B),
        "{:#?}",
        c.evidence
    );
    assert!(!any_tier_a(c));
    // No installer record: Likely even with the message file gone.
    assert_eq!(band(c), Band::Likely);
    // Windows' own source next to it is not offered.
    assert!(find(&found, &source_key("Application", "Application Error")).is_none());
}

#[test]
fn eventlog_source_with_msi_row_and_missing_file_safe() {
    let mut fx = machine();
    event_source(&mut fx, "Application", "App Service", &app_file("msg.dll"));
    let key = source_key("Application", "App Service");
    let mut world = World::new(fx);
    world.fp.msi = vec![msi_with_whole_key(&key, "RegEventSource")];
    let world = world.ready();
    let found = sources(&world);
    let c = get(&found, &key);
    assert!(
        has(
            c,
            EvidenceKind::InstallerManifest(ManifestKind::Msi),
            Tier::A
        ),
        "{:#?}",
        c.evidence
    );
    assert!(c.blockers.is_empty(), "{:?}", c.blockers);
    assert_eq!(band(c), Band::Safe);

    // The same source with its message file still there: Likely.
    let mut fx = machine();
    event_source(&mut fx, "Application", "App Service", &app_file("msg.dll"));
    fx.add_file(&app_file("msg.dll"), 10);
    let mut world = World::new(fx);
    world.fp.msi = vec![msi_with_whole_key(&key, "RegEventSource")];
    let world = world.ready();
    let found = sources(&world);
    let c = get(&found, &key);
    assert!(!any_tier_a(c), "{:#?}", c.evidence);
    assert_eq!(band(c), Band::Likely);
}

#[test]
fn eventlog_source_found_by_msi_row_alone() {
    // The walk did not run: the MSI row alone leads to the source, which must still name the app's
    // message file.
    let mut fx = machine();
    event_source(&mut fx, "Application", "App Service", &app_file("msg.dll"));
    let key = source_key("Application", "App Service");
    let mut world = World::new(fx);
    world.fp.msi = vec![msi_with_whole_key(&key, "RegEventSource")];
    let found = sources(&world);
    assert_eq!(band(get(&found, &key)), Band::Safe);
}

#[test]
fn eventlog_source_named_after_app_message_file_dotnet_nothing() {
    // Hostile (trap eventlog-shared-source): a source named after the app whose message file is the
    // .NET Framework's. Even the app's own MSI row on it does not make it the app's.
    let mut fx = machine();
    event_source(
        &mut fx,
        "Application",
        "App",
        r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll",
    );
    let key = source_key("Application", "App");
    let mut world = World::new(fx);
    world.fp.msi = vec![msi_with_whole_key(&key, "RegEventSource")];
    let world = world.ready();
    let found = sources(&world);
    assert!(found.is_empty(), "{:#?}", spots(&found));
}

#[test]
fn eventlog_multi_file_one_foreign_nothing() {
    let mut fx = machine();
    event_source(
        &mut fx,
        "Application",
        "App Service",
        &format!(
            r"{};%SystemRoot%\System32\kernel32.dll",
            app_file("msg.dll")
        ),
    );
    // Every message-file value counts: a foreign category file is as bad.
    event_source(&mut fx, "System", "App Driver", &app_file("msg.dll"));
    fx.set_value(
        &format!(r"{EVENTLOG_SET}\System\App Driver"),
        "CategoryMessageFile",
        RegData::from_expand_sz(r"%SystemRoot%\System32\wevtapi.dll"),
    );
    // An unexpanded variable is no path the scanner can vouch for.
    event_source(
        &mut fx,
        "Application",
        "App Unknown",
        &format!(r"{};%NOSUCHVAR%\x.dll", app_file("msg.dll")),
    );
    let world = World::new(fx).ready();
    let found = sources(&world);
    assert!(found.is_empty(), "{:#?}", spots(&found));

    // Two files, both the app's: offered.
    let mut fx = machine();
    event_source(
        &mut fx,
        "Application",
        "App Service",
        &format!(r"{}; {}", app_file("msg.dll"), app_file("msg2.dll")),
    );
    let world = World::new(fx).ready();
    assert_eq!(sources(&world).len(), 1);
}

#[test]
fn eventlog_log_key_never() {
    // The app made its own log, `AppLog`, with a source of the same name; its MSI removes the log whole
    // and a value on the log key names a file of the app.
    let mut fx = machine();
    let log_key = format!(r"{EVENTLOG_SET}\AppLog");
    fx.set_value(
        &log_key,
        "File",
        RegData::from_expand_sz(&app_file("AppLog.evtx")),
    );
    fx.set_value(
        &log_key,
        "EventMessageFile",
        RegData::from_expand_sz(&app_file("msg.dll")),
    );
    event_source(&mut fx, "AppLog", "AppLog", &app_file("msg.dll"));
    let mut world = World::new(fx);
    world.fp.msi = vec![msi_with_whole_key(&format!(r"{EVENTLOG}\AppLog"), "RegLog")];
    let world = world.ready();
    let found = world.diag();
    for never in [EVENTLOG.to_owned(), format!(r"{EVENTLOG}\AppLog")] {
        assert!(
            find(&found, &never).is_none(),
            "{never}: {:#?}",
            spots(&found)
        );
    }
    // The source below it is offered, and the log's whole-key row does not make it Safe.
    let c = get(&found, &source_key("AppLog", "AppLog"));
    assert!(
        !has(
            c,
            EvidenceKind::InstallerManifest(ManifestKind::Msi),
            Tier::A
        ),
        "{:#?}",
        c.evidence
    );
    assert_eq!(band(c), Band::Likely);
}

#[test]
fn eventlog_message_file_inside_another_app_is_blocked() {
    // The other product's folder lies inside the app's root (a nested product): its file is not the
    // app's to drop.
    let mut fx = machine();
    let nested = app_file(r"Plugins\Other");
    event_source(
        &mut fx,
        "Application",
        "App Plugin",
        &format!(r"{nested}\msg.dll"),
    );
    let mut world = World::new(fx);
    world.other_apps =
        purge_scan::framework::OtherApps::new(vec![purge_scan::framework::OtherApp {
            name: OTHER.into(),
            roots: vec![nested.clone()],
            ..Default::default()
        }]);
    let world = world.ready();
    let found = sources(&world);
    let c = get(&found, &source_key("Application", "App Plugin"));
    assert_eq!(band(c), Band::Blocked, "{:?}", c.blockers);
}
