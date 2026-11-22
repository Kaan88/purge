//! A whole fingerprint harvested under a view below Exact that knows the app's keys is a subset of the
//! no-baseline fingerprint (review BL-R1 M2, the suggestion deferred to BL-GATE). Stricter than the note's
//! list (anchors, tokens, table anchors, system objects, co-products, attributed subtrees): every field of
//! the fingerprint and of each co-product candidate is compared, only `warnings` and the recorded
//! `baseline_view` are left out; the views know every key and value of the machine, or a part of them.

use purge_index::baseline_view::{BaselineView, fixture};
use purge_source::sysobj::{MsiClassRow, MsiTables};
use serde_json::Value;

use super::msi::{OTHER, TOOL, component_row};
use super::shapes::{firewall_rule, inno_shape, other_app, service};
use super::*;

const DIR: &str = r"C:\Program Files\Acme\Tool";
const CLSID: &str = "{5AAAAAAA-0000-0000-0000-0000000000A1}";

/// An MSI app with COM table rows, a ProgID verb, a service and a firewall rule of its own, and a helper
/// MSI of the same vendor beside it (a co-product candidate).
fn rich() -> Fixture {
    let exe = format!(r"{DIR}\tool.exe");
    let b = msi_app(machine(), TOOL, "Acme Tool", Some(DIR));
    let b = files(b, TOOL, 1, &[&exe, &format!(r"{DIR}\toolsvc.exe")]);
    let class = MsiClassRow {
        clsid: CLSID.into(),
        context: "LocalServer32".into(),
        component: "Main".into(),
        progid: None,
        appid: None,
    };
    let tables = MsiTables {
        components: vec![component_row("Main", &comp(1))],
        classes: vec![class],
        progids: vec!["Acme.Tool.Doc".into()],
        ..MsiTables::default()
    };
    let b = with_tables(b, TOOL, tables)
        .sz(
            r"HKLM\SOFTWARE\Classes\Acme.Tool.Doc\shell\open\command",
            "",
            &format!(r#""{exe}" "%1""#),
        )
        .sz(
            &format!(r"HKLM\SOFTWARE\Classes\CLSID\{CLSID}\LocalServer32"),
            "",
            &exe,
        );
    let b = service(b, "AcmeToolSvc", &format!(r#""{DIR}\toolsvc.exe""#));
    let b = firewall_rule(
        b,
        "{0000BBBB-0000-0000-0000-000000000001}",
        "Acme Tool",
        &exe,
    );
    let b = msi_app(
        b,
        OTHER,
        "Acme Tool Helper",
        Some(r"C:\Program Files\Acme\Helper"),
    );
    let b = files(
        b,
        OTHER,
        10,
        &[
            r"C:\Program Files\Acme\Helper\h.exe",
            r"C:\Program Files\Acme\Helper\h.dll",
        ],
    );
    other_app(with_tables(
        b,
        OTHER,
        MsiTables {
            components: vec![component_row("Main", &comp(10))],
            ..MsiTables::default()
        },
    ))
    .build()
}

/// The fingerprint and the co-product candidates of `name`, as JSON, without the view-only fields.
fn harvested(f: &Fixture, name: &str, view: &BaselineView) -> Value {
    let doc = inventory_of(f);
    let entry = doc
        .entries
        .iter()
        .find(|e| e.display_name == name)
        .expect("the entry");
    let r = harvest_report_with(
        entry,
        &doc,
        Sources::of(f),
        view,
        Kb::shipped(),
        &HarvestOpts::default(),
    );
    let mut v = serde_json::json!({ "fp": r.fingerprint, "co": r.co_candidates });
    strip(&mut v);
    v
}

fn strip(v: &mut Value) {
    match v {
        Value::Object(m) => {
            m.remove("warnings");
            m.remove("baseline_view");
            m.values_mut().for_each(strip);
        }
        Value::Array(a) => a.iter_mut().for_each(strip),
        _ => {}
    }
}

/// Whether `below` claims nothing `none` does not: every array element is a sub-record of some element of
/// `none`'s array, scalars are equal, except that `fully_attributed` may only be lost.
fn sub(below: &Value, none: &Value) -> bool {
    match (below, none) {
        (Value::Object(b), Value::Object(n)) => {
            b.iter().all(|(k, bv)| match (k.as_str(), bv, n.get(k)) {
                ("fully_attributed", Value::Bool(false), Some(Value::Bool(_))) => true,
                (_, Value::Array(a), None) => a.is_empty(),
                (_, _, Some(nv)) => sub(bv, nv),
                (_, _, None) => bv.is_null(),
            })
        }
        (Value::Array(b), Value::Array(n)) => b.iter().all(|x| n.iter().any(|y| sub(x, y))),
        _ => below == none,
    }
}

/// Every key and value of the machine, as view entries (`CurrentControlSet` spelled as well).
fn machine_keys(f: &Fixture) -> Vec<String> {
    let doc: Value = serde_json::from_str(&f.to_json()).unwrap();
    let mut out = Vec::new();
    for (key, k) in doc["registry"]["keys"].as_object().unwrap() {
        let mut spell = vec![key.clone()];
        if let Some(rest) = key.strip_prefix(r"HKLM\SYSTEM\ControlSet001\") {
            spell.push(format!(r"HKLM\SYSTEM\CurrentControlSet\{rest}"));
        }
        for s in spell {
            for name in k
                .get("values")
                .and_then(Value::as_object)
                .into_iter()
                .flat_map(|m| m.keys())
            {
                out.push(fixture::value_entry(&s, name));
            }
            out.push(s);
        }
    }
    out
}

#[test]
fn a_whole_fingerprint_below_exact_is_a_subset_of_the_no_baseline_one() {
    let (e, b, u) = ("Professional", 26100, 1742);
    let mut changed = 0;
    for (name, f) in [
        ("Acme Tool", rich()),
        ("Tool", inno_shape()),
        ("Editor", super::shapes::nsis_shape()),
    ] {
        let none = harvested(&f, name, BaselineView::empty());
        let all = machine_keys(&f);
        for part in 0..4 {
            // All of it, then every second key (two halves) and every third.
            let keys: Vec<&str> = all
                .iter()
                .enumerate()
                .filter(|(i, _)| match part {
                    0 => true,
                    1 | 2 => i % 2 == part - 1,
                    _ => i % 3 == 0,
                })
                .map(|(_, k)| k.as_str())
                .collect();
            let views = [
                fixture::merged_view(e, b, u, &keys, &[]),
                fixture::merged_view(e, b, u, &[], &keys),
                fixture::local_view(e, b, u, &keys),
                fixture::none_view(e, b, u, &keys),
            ];
            for view in &views {
                let below = harvested(&f, name, view);
                assert!(
                    sub(&below, &none),
                    "{name} part {part} {}:\nbelow {below:#}\nnone {none:#}",
                    view.name()
                );
                if below != none {
                    // The comparison bites: what was taken away is missing the other way round.
                    assert!(!sub(&none, &below), "{name} part {part} {}", view.name());
                    changed += 1;
                }
            }
        }
        if name == "Acme Tool" {
            // The comparison bites: the parts the review names are there to be taken away.
            let fp = &none["fp"];
            for part in [
                "/anchors/clsids",
                "/anchors/progids",
                "/tokens",
                "/sys/services",
                "/sys/firewall_rules",
            ] {
                assert!(
                    fp.pointer(part)
                        .and_then(Value::as_array)
                        .is_some_and(|a| !a.is_empty()),
                    "{part}: {fp:#}"
                );
            }
            assert!(
                none["co"].as_array().is_some_and(|a| !a.is_empty()),
                "no co-product: {none:#}"
            );
        }
        if name == "Tool" {
            let attributed = none["fp"]["subtrees"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["fully_attributed"] == true);
            assert!(attributed, "no attributed subtree: {none:#}");
        }
    }
    assert!(changed > 0, "no view took anything away");
}
