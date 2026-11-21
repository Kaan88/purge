//! Tests of the baseline view: the truth table of `key_absent`, the union, the constructors' trust,
//! the directory entry point and the hashed-set round trip. The selection rule and the `view.json`
//! reader have their own tests beside them.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::baseline::HashedSets;
use crate::local_baseline::file::encode;
use crate::local_baseline::{
    BUILDER_VERSION, LocalHeader, LocalSource, Records, SourceLine, SourceStatus,
};

const SHIPPED_VIEW: &str = include_str!("../../../../kb/baselines/view.json");
const SYNTHETIC: &str = include_str!("../../tests/fixtures/Synthetic-12345.678.tsv");

/// The host of the design: no shipped baseline is exactly its.
fn host() -> HostOs {
    HostOs::new("Professional", 26300, 9974)
}

fn shipped_rules() -> ViewRules {
    ViewRules::parse(SHIPPED_VIEW).expect("the shipped view.json")
}

/// Rules with one area per line of `areas` (JSON objects).
fn rules_of(areas: &str) -> ViewRules {
    ViewRules::parse(&format!(
        "{{\"schema\":\"{VIEW_SCHEMA}\",\"neighbours\":{{\"max_build_distance\":1000,\"max_count\":3}},\
         \"areas\":[{areas}]}}"
    ))
    .expect("test rules")
}

/// The text of a shipped baseline with these keys.
fn shipped_text(edition: &str, build: u32, ubr: u32, keys: &[&str]) -> String {
    let mut text = format!("#purge-baseline 1\tT\tRIG\t{edition}\t{build}.{ubr}\n");
    for key in keys {
        text.push_str(&format!("K\t{}\n", key.replace('\\', "\\\\")));
    }
    text
}

fn shipped(edition: &str, build: u32, ubr: u32, keys: &[&str]) -> Baseline {
    Baseline::from_bytes(shipped_text(edition, build, ubr, keys).as_bytes()).expect("parses")
}

fn neighbour(edition: &str, build: u32, ubr: u32, keys: &[&str]) -> Neighbour {
    shipped(edition, build, ubr, keys).into()
}

fn ok_sources() -> Vec<SourceLine> {
    LocalSource::REQUIRED
        .map(|source| SourceLine {
            source,
            status: SourceStatus::Ok,
            items: 1,
            records: 1,
            skipped: 0,
            reasons: Vec::new(),
            facts: Vec::new(),
        })
        .to_vec()
}

fn local_header(os: &HostOs) -> LocalHeader {
    LocalHeader {
        built_at: "2026-11-21T00:00:00Z".into(),
        computer: "PC".into(),
        edition: os.edition.clone(),
        build: os.build,
        ubr: os.ubr,
        builder_version: BUILDER_VERSION.into(),
        source_id: "0123456789abcdef".into(),
    }
}

/// A local baseline of `os` with these `#src` lines and records, through the real file format.
fn local_from(os: &HostOs, sources: &[SourceLine], records: &Records) -> LocalBaseline {
    let enc = encode(&local_header(os), sources, records).expect("encodes");
    LocalBaseline::from_bytes(&enc.bytes).expect("reads back")
}

/// A complete local baseline of `os` with these keys.
fn local(os: &HostOs, keys: &[&str]) -> LocalBaseline {
    let mut records = Records::new();
    for key in keys {
        records.add_key(key);
    }
    local_from(os, &ok_sources(), &records)
}

/// The same with S3 incomplete.
fn incomplete_local(os: &HostOs, keys: &[&str]) -> LocalBaseline {
    let mut records = Records::new();
    for key in keys {
        records.add_key(key);
    }
    let mut sources = ok_sources();
    sources[2].status = SourceStatus::Incomplete;
    sources[2].reasons = vec!["3 keys not read whole (unreadable)".into()];
    local_from(os, &sources, &records)
}

fn gzip(text: &str) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(text.as_bytes()).unwrap();
    enc.finish().unwrap()
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("purge-view-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

// -------------------------------------------------------------------------------------------------
// The truth table
// -------------------------------------------------------------------------------------------------

/// Where a probe key lies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    /// In scope, in an area the shipped `view.json` marks `merged`.
    Marked,
    /// In scope, in an area that is not marked.
    Unmarked,
    /// Outside the capture scope.
    OutOfScope,
}

const PLACES: [Place; 3] = [Place::Marked, Place::Unmarked, Place::OutOfScope];

/// One probe key per (place, in the local baseline, in the neighbour).
fn probe(place: Place, in_local: bool, in_neighbour: bool) -> String {
    let tag = format!("tt{}{}", u8::from(in_local), u8::from(in_neighbour));
    match place {
        Place::Marked => format!(r"HKLM\SOFTWARE\Classes\CLSID\{{{tag}}}"),
        Place::Unmarked => format!(r"HKLM\SOFTWARE\Classes\.{tag}"),
        Place::OutOfScope => format!(r"HKLM\SYSTEM\CurrentControlSet\Enum\{tag}"),
    }
}

/// The probes a set holds: those with `in_local` (for the local baseline) or `in_neighbour`.
fn held(local_side: bool) -> Vec<String> {
    let mut keys = Vec::new();
    for place in PLACES {
        for other in [false, true] {
            keys.push(if local_side {
                probe(place, true, other)
            } else {
                probe(place, other, true)
            });
        }
    }
    keys
}

/// Trust × (in the local baseline, in a neighbour, in scope, area flag) → `Absence`, with the shipped
/// `view.json` (seven areas `merged`, none `local`).
#[test]
fn truth_table() {
    let rules = shipped_rules();
    let in_local = held(true);
    let in_local: Vec<&str> = in_local.iter().map(String::as_str).collect();
    let in_neighbour = held(false);
    let in_neighbour: Vec<&str> = in_neighbour.iter().map(String::as_str).collect();
    let both: Vec<&str> = in_local.iter().chain(&in_neighbour).copied().collect();
    let near = || vec![neighbour("Professional", 26340, 9882, &in_neighbour)];

    let exact = BaselineView::exact(shipped("Professional", 26300, 9974, &both));
    let merged = BaselineView::merged(&host(), local(&host(), &in_local), near(), &rules);
    let local_only = BaselineView::local(&host(), local(&host(), &in_local), &rules);
    let none_incomplete = BaselineView::assemble(
        &host(),
        Some(incomplete_local(&host(), &in_local)),
        near(),
        &rules,
    );
    let none_no_local = BaselineView::assemble(&host(), None, near(), &rules);
    let none_forced = BaselineView::none(&host(), Some(local(&host(), &in_local)), near(), &rules);
    let none_empty = BaselineView::assemble(&host(), None, Vec::new(), &rules);

    assert_eq!(exact.trust(), BaselineTrust::Exact);
    assert_eq!(merged.trust(), BaselineTrust::Merged);
    assert_eq!(local_only.trust(), BaselineTrust::Local);
    for none in [&none_incomplete, &none_no_local, &none_forced, &none_empty] {
        assert_eq!(none.trust(), BaselineTrust::None);
    }

    let mut rows = 0;
    for place in PLACES {
        for l in [false, true] {
            for n in [false, true] {
                let key = probe(place, l, n);
                let in_scope = place != Place::OutOfScope;
                let marked = place == Place::Marked;
                let row = format!("{place:?} in_local={l} in_neighbour={n}");

                // Exact: the one baseline holds every probe that is in either set.
                let want = match (l || n, in_scope) {
                    (true, _) => Absence::Present,
                    (false, true) => Absence::Proven,
                    (false, false) => Absence::Unknown,
                };
                assert_eq!(exact.key_absent(&key), want, "exact, {row}");

                // Merged: present from either set; inferred only in scope and in a marked area.
                let want = match (l || n, in_scope && marked) {
                    (true, _) => Absence::Present,
                    (false, true) => Absence::Inferred(BaselineTrust::Merged),
                    (false, false) => Absence::Unknown,
                };
                assert_eq!(merged.key_absent(&key), want, "merged, {row}");

                // Local: the neighbour is not there; no area is marked `local`.
                let want = if l {
                    Absence::Present
                } else {
                    Absence::Unknown
                };
                assert_eq!(local_only.key_absent(&key), want, "local, {row}");

                // None: presence from whatever exists, absence never.
                for (name, view, present) in [
                    ("none (incomplete local)", &none_incomplete, l || n),
                    ("none (no local)", &none_no_local, n),
                    ("none (forced)", &none_forced, l || n),
                    ("none (empty)", &none_empty, false),
                ] {
                    let want = if present {
                        Absence::Present
                    } else {
                        Absence::Unknown
                    };
                    assert_eq!(view.key_absent(&key), want, "{name}, {row}");
                    assert_eq!(view.has_key(&key), present, "{name}, {row}");
                }

                // Below Exact nothing is ever proven; `Present` is exactly `has_key`.
                for view in [&merged, &local_only, &none_incomplete, &none_no_local] {
                    assert_ne!(view.key_absent(&key), Absence::Proven, "{row}");
                    assert_eq!(
                        view.key_absent(&key).is_present(),
                        view.has_key(&key),
                        "{row}"
                    );
                }
                rows += 1;
            }
        }
    }
    assert_eq!(rows, 12);
}

/// The Local column with an area marked `local` (none is today): inferred at Local there and only
/// there, and a `merged` flag does not count at Local nor a `local` flag at Merged.
#[test]
fn truth_table_with_a_local_area() {
    let rules = rules_of(
        r#"{"id":"l","prefixes":["hklm\\software\\classes\\clsid"],"local":true},
           {"id":"m","prefixes":["hklm\\software\\classes\\interface"],"merged":true},
           {"id":"b","prefixes":["hklm\\software\\classes\\appid"],"merged":true,"local":true},
           {"id":"n","prefixes":["hklm\\software\\classes"]}"#,
    );
    let clsid = r"HKLM\SOFTWARE\Classes\CLSID\{x}";
    let interface = r"HKLM\SOFTWARE\Classes\Interface\{x}";
    let appid = r"HKLM\SOFTWARE\Classes\AppID\{x}";
    let progid = r"HKLM\SOFTWARE\Classes\x.y";
    let outside = r"HKLM\SOFTWARE\Vendor";
    let local_view = BaselineView::local(&host(), local(&host(), &[]), &rules);
    assert_eq!(local_view.trust(), BaselineTrust::Local);
    let inferred = Absence::Inferred(BaselineTrust::Local);
    assert_eq!(local_view.key_absent(clsid), inferred);
    assert_eq!(local_view.key_absent(interface), Absence::Unknown);
    assert_eq!(local_view.key_absent(appid), inferred);
    assert_eq!(local_view.key_absent(progid), Absence::Unknown);
    assert_eq!(local_view.key_absent(outside), Absence::Unknown);

    let merged = BaselineView::merged(
        &host(),
        local(&host(), &[]),
        vec![neighbour("Professional", 26340, 9882, &[])],
        &rules,
    );
    assert_eq!(merged.trust(), BaselineTrust::Merged);
    let inferred = Absence::Inferred(BaselineTrust::Merged);
    assert_eq!(merged.key_absent(clsid), Absence::Unknown);
    assert_eq!(merged.key_absent(interface), inferred);
    assert_eq!(merged.key_absent(appid), inferred);
    assert_eq!(merged.key_absent(progid), Absence::Unknown);
    // In scope, but in no area at all: never marked.
    assert_eq!(merged.key_absent(outside), Absence::Unknown);
    assert_eq!(merged.area_of(outside), None);
    assert_eq!(merged.area_of(clsid), Some("l"));
}

/// With `view.json` missing or refused no area exists: the trust is what the parts support, and
/// absence is never inferred.
#[test]
fn closed_rules_infer_nothing() {
    let view = BaselineView::merged(
        &host(),
        local(&host(), &[r"HKLM\SOFTWARE\Classes\CLSID\{in}"]),
        vec![neighbour("Professional", 26340, 9882, &[])],
        &ViewRules::closed(),
    );
    assert_eq!(view.trust(), BaselineTrust::Merged);
    assert_eq!(
        view.key_absent(r"HKLM\SOFTWARE\Classes\CLSID\{in}"),
        Absence::Present
    );
    for key in [
        r"HKLM\SOFTWARE\Classes\CLSID\{out}",
        r"HKLM\SOFTWARE\Vendor",
        r"HKLM\SOFTWARE\WOW6432Node\Vendor",
        r"HKU\.DEFAULT\Software\Vendor",
    ] {
        assert_eq!(view.key_absent(key), Absence::Unknown, "{key}");
    }
}

/// Spellings: an unbound root is never inferred; a bound one is normalised before its area is looked
/// up; the twin of a 32-bit spelling counts as presence.
#[test]
fn spellings_of_the_asked_key() {
    let rules = shipped_rules();
    let view = BaselineView::merged(
        &host(),
        local(
            &host(),
            &[
                r"HKLM\SOFTWARE\Classes\CLSID\{known}",
                r"HKLM\SOFTWARE\Vendor\Shared",
            ],
        ),
        vec![neighbour("Professional", 26340, 9882, &[])],
        &rules,
    );
    let inferred = Absence::Inferred(BaselineTrust::Merged);
    assert_eq!(
        view.key_absent(r"HKLM\SOFTWARE\Classes\CLSID\{new}"),
        inferred
    );
    assert_eq!(
        view.key_absent(r"HKEY_LOCAL_MACHINE\software\CLASSES\clsid\{NEW}\"),
        inferred
    );
    // The link spelling of the 32-bit classes is the marked area `classes-wow6432node`.
    assert_eq!(
        view.key_absent(r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{new}"),
        inferred
    );
    assert_eq!(
        view.area_of(r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{new}"),
        Some("classes-wow6432node")
    );
    // The 64-bit twin is known: the 32-bit spelling is present, as `Baseline::has_key` has it.
    assert_eq!(
        view.key_absent(r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{known}"),
        Absence::Present
    );
    assert_eq!(
        view.key_absent(r"HKLM\SOFTWARE\WOW6432Node\Vendor\Shared"),
        Absence::Present
    );
    assert!(!view.has_key_exact_view(r"HKLM\SOFTWARE\WOW6432Node\Vendor\Shared"));
    assert!(view.has_key_exact_view(r"HKLM\SOFTWARE\Vendor\Shared"));
    // HKCR names the machine classes or the user's: present from either, never inferred.
    assert_eq!(view.key_absent(r"HKCR\CLSID\{known}"), Absence::Present);
    assert_eq!(view.key_absent(r"HKCR\CLSID\{new}"), Absence::Unknown);
    assert_eq!(
        view.key_absent(r"HKEY_CLASSES_ROOT\CLSID\{new}"),
        Absence::Unknown
    );
    // The user's hive: bound, in scope, in an unmarked area.
    assert_eq!(view.key_absent(r"HKCU\Software\Vendor"), Absence::Unknown);
    assert_eq!(
        view.key_absent(r"HKU\S-1-5-21-1-2-3-1001\Software\Vendor"),
        Absence::Unknown
    );
    // Not a registry key of any hive the view knows.
    for key in [
        "",
        "HKLM",
        r"HKXX\SOFTWARE\Classes\CLSID\{new}",
        r"HKLM\SAM\SAM",
        r"SOFTWARE\Vendor",
    ] {
        assert_eq!(view.key_absent(key), Absence::Unknown, "{key:?}");
    }
}

// -------------------------------------------------------------------------------------------------
// Unreadable keys (BL-RM M4)
// -------------------------------------------------------------------------------------------------

fn s3_facts(sources: &mut [SourceLine], unreadable: &str, keys: &str) {
    sources[2].facts = vec![
        ("unreadable".into(), unreadable.into()),
        ("unreadable-by-design".into(), unreadable.into()),
        ("unreadable-keys".into(), keys.into()),
        ("vanished-keys".into(), String::new()),
    ];
}

/// At and below a key the builder could not read the view knows nothing, even in a marked area.
#[test]
fn unknown_below_an_unreadable_key() {
    // No shipped area that holds such a key is marked today; mark them here.
    let rules = rules_of(
        r#"{"id":"default","prefixes":["hku\\.default"],"merged":true},
           {"id":"software","prefixes":["hklm\\software"],"merged":true}"#,
    );
    let mut sources = ok_sources();
    s3_facts(
        &mut sources,
        "2",
        r"HKU\.DEFAULT\Software\Microsoft\SystemCertificates\Root\ProtectedRoots, HKLM\SOFTWARE\Sealed",
    );
    let mut records = Records::new();
    records.add_key(r"HKU\.DEFAULT\Software\Microsoft\SystemCertificates\Root\ProtectedRoots");
    let view = BaselineView::merged(
        &host(),
        local_from(&host(), &sources, &records),
        vec![neighbour("Professional", 26340, 9882, &[])],
        &rules,
    );
    assert_eq!(view.trust(), BaselineTrust::Merged, "{:?}", view.warnings());
    let inferred = Absence::Inferred(BaselineTrust::Merged);
    let roots = r"HKU\.DEFAULT\Software\Microsoft\SystemCertificates\Root";
    // The unreadable key itself is a record (its parent listed it).
    assert_eq!(
        view.key_absent(&format!(r"{roots}\ProtectedRoots")),
        Absence::Present
    );
    assert_eq!(
        view.key_absent(&format!(r"{roots}\ProtectedRoots\Certificates")),
        Absence::Unknown
    );
    assert_eq!(
        view.key_absent(&format!(r"{roots}\protectedroots\a\b\c")),
        Absence::Unknown
    );
    // The same key by its other spelling.
    assert_eq!(
        view.key_absent(
            r"HKU\S-1-5-18\Software\Microsoft\SystemCertificates\Root\ProtectedRoots\x"
        ),
        Absence::Unknown
    );
    // Beside it, and a key that only starts with the same letters, are inferred as elsewhere.
    assert_eq!(view.key_absent(&format!(r"{roots}\Certificates")), inferred);
    assert_eq!(
        view.key_absent(&format!(r"{roots}\ProtectedRootsX")),
        inferred
    );
    // An unreadable key that is not itself a record: unknown at it and below it, and below its
    // 32-bit spelling, whose twin it is.
    assert_eq!(view.key_absent(r"HKLM\SOFTWARE\Sealed"), Absence::Unknown);
    assert_eq!(view.key_absent(r"HKLM\SOFTWARE\Sealed\x"), Absence::Unknown);
    assert_eq!(
        view.key_absent(r"HKLM\SOFTWARE\WOW6432Node\Sealed\x"),
        Absence::Unknown
    );
    assert_eq!(view.key_absent(r"HKLM\SOFTWARE\Open\x"), inferred);
}

/// `#src` lines that cannot be relied on to name every unreadable key give trust None.
#[test]
fn unreadable_keys_that_are_not_all_named_give_trust_none() {
    let rules = shipped_rules();
    let near = || vec![neighbour("Professional", 26340, 9882, &[])];
    let view_with = |unreadable: &str, keys: &str| {
        let mut sources = ok_sources();
        s3_facts(&mut sources, unreadable, keys);
        BaselineView::merged(
            &host(),
            local_from(&host(), &sources, &Records::new()),
            near(),
            &rules,
        )
    };
    let fine = view_with("1", r"HKU\.DEFAULT\Software\A");
    assert_eq!(fine.trust(), BaselineTrust::Merged, "{:?}", fine.warnings());
    assert_eq!(view_with("0", "").trust(), BaselineTrust::Merged);
    for (unreadable, keys, why) in [
        ("2", r"HKU\.DEFAULT\Software\A", "more counted than named"),
        ("17", "", "none named"),
        (
            "many",
            r"HKU\.DEFAULT\Software\A",
            "the count is not a number",
        ),
        ("1", r"Software\A", "no root"),
        (
            "1",
            r"C:\Users\Default\NTUSER.DAT\Software\A",
            "a file path",
        ),
        ("1", r"HKU\.DEFAULT\Software\A,B", "a name that held a `;`"),
        (
            "2",
            r"HKU\.DEFAULT\Software\A, B\C",
            "a name that held `, `",
        ),
    ] {
        let view = view_with(unreadable, keys);
        assert_eq!(view.trust(), BaselineTrust::None, "{why}");
        assert!(
            view.warnings()
                .iter()
                .any(|w| w.contains("unreadable keys")),
            "{why}: {:?}",
            view.warnings()
        );
        assert_eq!(
            view.key_absent(r"HKLM\SOFTWARE\Classes\CLSID\{x}"),
            Absence::Unknown,
            "{why}"
        );
    }
}

// -------------------------------------------------------------------------------------------------
// Trust from the parts
// -------------------------------------------------------------------------------------------------

/// L2: an incomplete local baseline gives trust None and still answers presence.
#[test]
fn an_incomplete_local_baseline_is_presence_only() {
    let rules = shipped_rules();
    let own = r"HKLM\SOFTWARE\Classes\CLSID\{windows-own}";
    let view = BaselineView::merged(
        &host(),
        incomplete_local(&host(), &[own]),
        vec![neighbour(
            "Professional",
            26340,
            9882,
            &[r"HKLM\SOFTWARE\Classes\CLSID\{near}"],
        )],
        &rules,
    );
    assert_eq!(view.trust(), BaselineTrust::None);
    assert!(view.has_key(own));
    assert!(view.has_segment("{windows-own}"));
    assert!(view.has_token("windows-own"));
    assert!(view.has_key(r"HKLM\SOFTWARE\Classes\CLSID\{near}"));
    assert_eq!(view.key_absent(own), Absence::Present);
    assert_eq!(
        view.key_absent(r"HKLM\SOFTWARE\Classes\CLSID\{other}"),
        Absence::Unknown
    );
    assert!(
        view.warnings()
            .iter()
            .any(|w| w.contains("incomplete") && w.contains("S3")),
        "{:?}",
        view.warnings()
    );
    // The same without a neighbour.
    let view = BaselineView::local(&host(), incomplete_local(&host(), &[own]), &rules);
    assert_eq!(view.trust(), BaselineTrust::None);
    assert!(view.has_key(own));
    // A source line missing altogether is incomplete too.
    let mut sources = ok_sources();
    sources.remove(3);
    let view = BaselineView::local(
        &host(),
        local_from(&host(), &sources, &Records::new()),
        &rules,
    );
    assert_eq!(view.trust(), BaselineTrust::None);
}

/// A local baseline of another Windows never supports absence here; its presence is still used.
#[test]
fn a_local_baseline_of_another_windows_is_presence_only() {
    let rules = shipped_rules();
    let near = || vec![neighbour("Professional", 26340, 9882, &[])];
    let key = r"HKLM\SOFTWARE\Classes\CLSID\{k}";
    for other in [
        HostOs::new("Professional", 26300, 9973),
        HostOs::new("Professional", 26301, 9974),
        HostOs::new("Core", 26300, 9974),
    ] {
        let view = BaselineView::merged(&host(), local(&other, &[key]), near(), &rules);
        assert_eq!(view.trust(), BaselineTrust::None, "{other:?}");
        assert!(view.has_key(key));
        assert_eq!(
            view.key_absent(r"HKLM\SOFTWARE\Classes\CLSID\{x}"),
            Absence::Unknown
        );
    }
    // The edition compares as the exact loader compares it.
    let same = HostOs::new("PROFESSIONAL", 26300, 9974);
    let view = BaselineView::merged(&host(), local(&same, &[key]), near(), &rules);
    assert_eq!(view.trust(), BaselineTrust::Merged);
}

/// The constructors apply the selection rule again: the exact baseline is never mixed into a union,
/// a baseline beyond the limit and those beyond the count are left out.
#[test]
fn neighbours_are_put_through_the_rule() {
    let rules = shipped_rules();
    let exact_key = r"HKLM\SOFTWARE\Classes\CLSID\{only-in-exact}";
    let far_key = r"HKLM\SOFTWARE\Classes\CLSID\{only-in-far}";
    let view = BaselineView::merged(
        &host(),
        local(&host(), &[]),
        vec![
            neighbour("Professional", 26300, 9974, &[exact_key]),
            neighbour("Professional", 22631, 1, &[far_key]),
        ],
        &rules,
    );
    // Nothing qualifies: the trust is Local, and neither set answers presence.
    assert_eq!(view.trust(), BaselineTrust::Local);
    assert!(view.neighbour_names().is_empty());
    assert!(!view.has_key(exact_key));
    assert!(!view.has_key(far_key));
    assert_eq!(view.warnings().len(), 2, "{:?}", view.warnings());

    let many: Vec<Neighbour> = (1..=5)
        .map(|i| neighbour("Professional", 26300 + i, 1, &[]))
        .chain([neighbour("EnterpriseSEval", 26300, 1, &[])])
        .collect();
    let view = BaselineView::merged(&host(), local(&host(), &[]), many, &rules);
    assert_eq!(view.trust(), BaselineTrust::Merged);
    assert_eq!(
        view.neighbour_names(),
        [
            "EnterpriseSEval-26300.1",
            "Professional-26301.1",
            "Professional-26302.1"
        ]
    );
    assert_eq!(view.name(), "local-Professional-26300.9974+3");
    assert_eq!(view.local_id(), Some("0123456789abcdef"));
    assert_eq!(view.warnings().len(), 3);
}

#[test]
fn names_and_trust_order() {
    let rules = shipped_rules();
    let exact = BaselineView::exact(shipped("Professional", 26340, 9882, &[]));
    assert_eq!(exact.name(), "Professional-26340.9882");
    assert_eq!(exact.local_id(), None);
    assert!(exact.neighbour_names().is_empty());
    assert!(exact.warnings().is_empty());
    let near = || vec![neighbour("Professional", 26340, 9882, &[])];
    assert_eq!(
        BaselineView::assemble(&host(), None, near(), &rules).name(),
        "none+1"
    );
    assert_eq!(
        BaselineView::assemble(&host(), None, Vec::new(), &rules).name(),
        "none"
    );
    assert_eq!(
        BaselineView::local(&host(), local(&host(), &[]), &rules).name(),
        "local-Professional-26300.9974"
    );
    use BaselineTrust as T;
    for (a, b, weaker) in [
        (T::Exact, T::Merged, T::Merged),
        (T::Merged, T::Local, T::Local),
        (T::Local, T::None, T::None),
        (T::Exact, T::None, T::None),
        (T::Merged, T::Merged, T::Merged),
        (T::Exact, T::Exact, T::Exact),
    ] {
        assert_eq!(a.weaker(b), weaker);
        assert_eq!(b.weaker(a), weaker);
    }
    assert_eq!(
        [T::Exact, T::Merged, T::Local, T::None].map(BaselineTrust::as_str),
        ["exact", "merged", "local", "none"]
    );
}

// -------------------------------------------------------------------------------------------------
// L3: the Exact view is the baseline
// -------------------------------------------------------------------------------------------------

const KEYS: &[&str] = &[
    r"HKLM\SOFTWARE\Classes\.txt",
    r"hklm\software\CLASSES\.TXT",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.txt\",
    r"HKLM\SOFTWARE\Classes\.txt\OpenWithProgids",
    r"HKLM\SOFTWARE\Classes\.tx",
    r"HKLM\SOFTWARE\Classes\.py",
    r"HKLM\SOFTWARE\Classes\txtfile",
    r"HKLM\SOFTWARE\Classes\txtfile\shell\open\command",
    r"HKLM\SOFTWARE\Classes\CLSID\{00021401-0000-0000-C000-000000000046}",
    r"HKLM\SOFTWARE\Classes\CLSID\{11111111-0000-0000-C000-000000000046}",
    r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{00021401-0000-0000-C000-000000000046}",
    r"HKLM\SOFTWARE\WOW6432Node\Classes\.txt",
    r"HKLM\SOFTWARE\WOW6432Node\Classes",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\ProfileList",
    r"HKLM\SOFTWARE\WOW6432Node\Vendor",
    r"HKLM\SOFTWARE\Classes\MIME\Database\Content Type\text/plain",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-9-9-9-1001",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip",
    r"HKLM\SYSTEM\ControlSet002\Services\Tcpip",
    r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
    r"HKLM\SYSTEM\CurrentControlSet\Enum\Root",
    r"HKLM\SYSTEM\CurrentControlSet\Services\Nope",
    r"HKLM\SYSTEM\Setup",
    r"HKLM\SAM\SAM",
    r"HKU\.DEFAULT\Environment",
    r"HKU\S-1-5-18\Environment",
    r"HKU\S-1-5-19\Environment",
    r"HKU\S-1-5-20\Environment",
    r"HKU\S-1-5-21-9-9-9-1001\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Vendor",
    r"HKU\S-1-5-21-9-9-9-1001_Classes\Local Settings",
    r"HKCU\Software\Classes\Local Settings",
    r"HKCR\.txt",
    r"HKCR\Local Settings",
    r"HKCR\.py",
    r"HKEY_CLASSES_ROOT\txtfile",
    r"HKXX\.txt",
    "HKLM",
    "",
];

const VALUES: &[(&str, &str)] = &[
    (r"HKLM\SOFTWARE\Classes\.txt", ""),
    (r"HKLM\SOFTWARE\Classes\.txt", "Content Type"),
    (r"HKLM\SOFTWARE\Classes\.txt", "content type"),
    (r"HKLM\SOFTWARE\Classes\.txt", "PerceivedType"),
    (r"HKCR\.txt", "Content Type"),
    (r"HKLM\SOFTWARE\Classes\.txt\OpenWithProgids", "txtfile"),
    (r"HKLM\SOFTWARE\Classes\txtfile\shell\open\command", ""),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "C:\\Tools\\a\tb",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "über größe",
    ),
    (
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "Über Größe",
    ),
    (r"HKLM\SYSTEM\ControlSet001\Services\Tcpip", "ImagePath"),
    (r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip", "Start"),
    (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "OneDriveSetup",
    ),
    (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "Other",
    ),
    ("", ""),
];

const PATHS: &[&str] = &[
    r"C:\Windows\System32",
    r"c:\windows\system32\",
    r"\\?\C:\Windows\System32\notepad.exe",
    r"C:/Windows/explorer.exe",
    r"C:\Windows\System32\nope.exe",
    r"C:\Program Files\Common Files",
    r"C:\Users\someone\AppData\Local\Microsoft",
    r"C:\Users\someone\NTUSER.DAT",
    r"C:\Users\Public\Desktop",
    r"C:\Users\Public\Documents",
    r"D:\Profiles\someone\AppData\Local\Microsoft",
    r"D:\Windows\System32",
    "",
];

const NAMES: &[&str] = &[
    "notepad.exe",
    "NOTEPAD.EXE",
    "txtfile",
    ".txt",
    "Content Type",
    "{00021401-0000-0000-C000-000000000046}",
    "00021401-0000-0000-C000-000000000046",
    "{00021401-0000-0000-c000-000000000046}",
    "{11111111-0000-0000-C000-000000000046}",
    "S-1-5-21-1111111111-2222222222-3333333333-1000",
    "text/plain",
    "plain",
    "text",
    "Tcpip",
    "ImagePath",
    "OneDriveSetup",
    "System32",
    "nope",
    " ",
    "{}",
    "",
];

/// Asserts that `view` answers every public question about every probe as `baseline` does.
fn assert_presence_equals(view: &BaselineView, baseline: &Baseline, what: &str) {
    for key in KEYS {
        assert_eq!(
            view.has_key(key),
            baseline.has_key(key),
            "{what}: has_key {key:?}"
        );
        assert_eq!(
            view.has_key_exact_view(key),
            baseline.has_key_exact_view(key),
            "{what}: has_key_exact_view {key:?}"
        );
    }
    for (key, name) in VALUES {
        assert_eq!(
            view.has_value(key, name),
            baseline.has_value(key, name),
            "{what}: has_value {key:?} {name:?}"
        );
    }
    for path in PATHS {
        assert_eq!(
            view.has_path(path),
            baseline.has_path(path),
            "{what}: has_path {path:?}"
        );
        assert_eq!(
            view.path_kind(path),
            baseline.path_kind(path),
            "{what}: path_kind {path:?}"
        );
        for profile in [r"D:\Profiles\someone", r"C:\Users\someone", ""] {
            assert_eq!(
                view.has_profile_path(profile, path),
                baseline.has_profile_path(profile, path),
                "{what}: has_profile_path {profile:?} {path:?}"
            );
        }
    }
    for name in NAMES {
        assert_eq!(
            view.has_segment(name),
            baseline.has_segment(name),
            "{what}: has_segment {name:?}"
        );
        assert_eq!(
            view.has_token(name),
            baseline.has_token(name),
            "{what}: has_token {name:?}"
        );
    }
}

/// L3: on the synthetic fixture the Exact view returns, for every public method, exactly what the
/// baseline returns, and `key_absent` is the old `!has_key && key_in_scope`.
#[test]
fn the_exact_view_equals_the_baseline() {
    let baseline = Baseline::from_bytes(SYNTHETIC.as_bytes()).unwrap();
    let view = BaselineView::exact(baseline.clone());
    assert_eq!(view.trust(), BaselineTrust::Exact);
    assert_eq!(view.name(), "Synthetic-12345.678");
    assert_presence_equals(&view, &baseline, "exact");
    let (mut present, mut proven, mut unknown) = (0, 0, 0);
    for key in KEYS {
        let want = if baseline.has_key(key) {
            present += 1;
            Absence::Present
        } else if Baseline::key_in_scope(key) {
            proven += 1;
            Absence::Proven
        } else {
            unknown += 1;
            Absence::Unknown
        };
        assert_eq!(view.key_absent(key), want, "{key:?}");
        assert_eq!(view.area_of(key), None);
    }
    assert!(
        present >= 10 && proven >= 10 && unknown >= 4,
        "{present} {proven} {unknown}"
    );
    let mut with_data = 0;
    for (key, name) in VALUES {
        assert_eq!(
            view.exact_value(key, name),
            baseline.value(key, name),
            "{key:?} {name:?}"
        );
        with_data += usize::from(view.exact_value(key, name).is_some());
    }
    assert!(with_data >= 8, "{with_data}");
    assert_eq!(
        view.exact_value(r"HKLM\SOFTWARE\Classes\.txt", "Content Type")
            .map(|v| v.hash_hex()),
        Some("0123456789abcdef".to_owned())
    );
}

/// The union over one set answers presence as that set does (the union adds nothing of its own), and
/// never gives a value's data.
#[test]
fn a_union_of_one_set_answers_presence_as_the_set() {
    let baseline = Baseline::from_bytes(SYNTHETIC.as_bytes()).unwrap();
    // The fixture is of build 12345; a host one build away takes it as its only neighbour.
    let near_host = HostOs::new("Synthetic", 12346, 1);
    let view = BaselineView::assemble(
        &near_host,
        None,
        vec![baseline.clone().into()],
        &shipped_rules(),
    );
    assert_eq!(view.trust(), BaselineTrust::None);
    assert_eq!(view.neighbour_names(), ["Synthetic-12345.678"]);
    assert_presence_equals(&view, &baseline, "one neighbour");
    for key in KEYS {
        let want = if baseline.has_key(key) {
            Absence::Present
        } else {
            Absence::Unknown
        };
        assert_eq!(view.key_absent(key), want, "{key:?}");
    }
    for (key, name) in VALUES {
        assert_eq!(view.exact_value(key, name), None);
    }
}

// -------------------------------------------------------------------------------------------------
// L1: a set only adds
// -------------------------------------------------------------------------------------------------

/// A small deterministic generator (the workspace has no property-test crate).
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn pick<'a>(&mut self, from: &[&'a str], share: u64) -> Vec<&'a str> {
        from.iter()
            .copied()
            .filter(|_| self.next() % 100 < share)
            .collect()
    }
}

/// Everything a view says about the probes that is a "yes".
fn yeses(view: &BaselineView, keys: &[&str], paths: &[&str], names: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for key in keys {
        for (what, yes) in [
            ("has_key", view.has_key(key)),
            ("has_key_exact_view", view.has_key_exact_view(key)),
            (
                "key_absent=Present",
                view.key_absent(key) == Absence::Present,
            ),
            ("has_value", view.has_value(key, "Name")),
        ] {
            if yes {
                out.push(format!("{what} {key}"));
            }
        }
    }
    for path in paths {
        if view.has_path(path) {
            out.push(format!("has_path {path}"));
        }
        if view.has_profile_path(r"C:\Users\u", path) {
            out.push(format!("has_profile_path {path}"));
        }
    }
    for name in names {
        if view.has_segment(name) {
            out.push(format!("has_segment {name}"));
        }
        if view.has_token(name) {
            out.push(format!("has_token {name}"));
        }
    }
    out
}

/// Property: adding a set (a neighbour, or the local baseline in any state) never turns `Present`
/// into anything else, nor any presence answer from yes to no.
#[test]
fn adding_a_set_never_takes_presence_away() {
    let rules = shipped_rules();
    let keys: Vec<String> = (0..8)
        .flat_map(|i| {
            [
                format!(r"HKLM\SOFTWARE\Classes\CLSID\{{p{i}}}"),
                format!(r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{{p{i}}}"),
                format!(r"HKLM\SOFTWARE\Vendor{i}"),
                format!(r"HKLM\SOFTWARE\WOW6432Node\Vendor{i}"),
                format!(r"HKLM\SOFTWARE\Classes\.p{i}"),
                format!(r"HKU\.DEFAULT\Software\P{i}"),
                format!(r"HKLM\SYSTEM\CurrentControlSet\Enum\P{i}"),
            ]
        })
        .collect();
    let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
    let paths: Vec<String> = (0..6)
        .flat_map(|i| {
            [
                format!(r"C:\Windows\System32\p{i}.dll"),
                format!(r"C:\Users\u\p{i}"),
            ]
        })
        .collect();
    let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
    let names: Vec<String> = (0..8)
        .flat_map(|i| [format!("{{p{i}}}"), format!("p{i}")])
        .collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();

    let mut rng = Lcg(0x5eed);
    let mut inferred_seen = 0;
    for round in 0..40 {
        let mut set = |edition: &str, build: u32| {
            let mut text = shipped_text(edition, build, 1, &rng.pick(&keys, 30));
            for key in rng.pick(&keys, 15) {
                text.push_str(&format!(
                    "V\t{}\tName\t1\t0000000000000001\n",
                    key.replace('\\', "\\\\")
                ));
            }
            for path in rng.pick(&paths, 30) {
                text.push_str(&format!("F\t{}\n", path.replace('\\', "\\\\")));
            }
            Baseline::from_bytes(text.as_bytes()).unwrap()
        };
        let a: Neighbour = set("Professional", 26340).into();
        let b: Neighbour = set("EnterpriseSEval", 26100).into();
        let local_keys = rng.pick(&keys, 30);
        let complete = round % 2 == 0;
        let local_set = || {
            if complete {
                local(&host(), &local_keys)
            } else {
                incomplete_local(&host(), &local_keys)
            }
        };
        // Each step adds one set to the step before it.
        let steps = [
            BaselineView::assemble(&host(), None, Vec::new(), &rules),
            BaselineView::assemble(&host(), None, vec![a.clone()], &rules),
            BaselineView::assemble(&host(), None, vec![a.clone(), b.clone()], &rules),
            BaselineView::assemble(
                &host(),
                Some(local_set()),
                vec![a.clone(), b.clone()],
                &rules,
            ),
        ];
        // And the other order: the local baseline first, then the neighbours.
        let other = [
            BaselineView::assemble(&host(), Some(local_set()), Vec::new(), &rules),
            BaselineView::assemble(&host(), Some(local_set()), vec![b.clone()], &rules),
            BaselineView::assemble(&host(), Some(local_set()), vec![a, b], &rules),
        ];
        assert!(yeses(&steps[0], &keys, &paths, &names).is_empty());
        for chain in [&steps[..], &other[..]] {
            for pair in chain.windows(2) {
                let before = yeses(&pair[0], &keys, &paths, &names);
                let after = yeses(&pair[1], &keys, &paths, &names);
                for yes in &before {
                    assert!(
                        after.contains(yes),
                        "round {round}: {yes} was lost by adding a set"
                    );
                }
            }
        }
        // The chains end in the same view, whatever the order the sets came in.
        assert_eq!(
            yeses(&steps[3], &keys, &paths, &names),
            yeses(&other[2], &keys, &paths, &names),
            "round {round}"
        );
        let last = &steps[3];
        assert_eq!(
            last.trust(),
            if complete {
                BaselineTrust::Merged
            } else {
                BaselineTrust::None
            }
        );
        for key in &keys {
            // No answer is ever a proof, and an inference needs the complete local baseline.
            let answer = last.key_absent(key);
            assert_ne!(answer, Absence::Proven);
            if let Absence::Inferred(trust) = answer {
                assert!(
                    complete && trust == BaselineTrust::Merged,
                    "round {round}: {key}"
                );
                assert!(!last.has_key(key));
                inferred_seen += 1;
            }
        }
    }
    assert!(
        inferred_seen > 50,
        "the rounds exercised inference ({inferred_seen})"
    );
}

// -------------------------------------------------------------------------------------------------
// The directory entry point
// -------------------------------------------------------------------------------------------------

fn write_shipped(dir: &std::path::Path, edition: &str, build: u32, ubr: u32, keys: &[&str]) {
    fs::write(
        dir.join(Baseline::file_name(edition, build, ubr)),
        gzip(&shipped_text(edition, build, ubr, keys)),
    )
    .unwrap();
}

/// L3: with the exact baseline in the directory the view is Exact, nothing else is read and the
/// local baseline is not asked for.
#[test]
fn open_with_an_exact_baseline_does_not_touch_the_local_one() {
    let dir = temp_dir("open-exact");
    let key = r"HKLM\SOFTWARE\Classes\CLSID\{exact}";
    let near_key = r"HKLM\SOFTWARE\Classes\CLSID\{near}";
    write_shipped(&dir, "Professional", 26300, 9974, &[key]);
    write_shipped(&dir, "Professional", 26340, 9882, &[near_key]);
    // No view.json, and one that is refused: an Exact view needs neither.
    let asked = AtomicBool::new(false);
    for attempt in 0..2 {
        let view = BaselineView::open(&dir, &host(), || {
            asked.store(true, Ordering::SeqCst);
            Some(local(&host(), &[near_key]))
        });
        assert_eq!(view.trust(), BaselineTrust::Exact, "attempt {attempt}");
        assert!(view.warnings().is_empty(), "{:?}", view.warnings());
        assert!(view.has_key(key));
        assert!(!view.has_key(near_key), "the neighbour is not mixed in");
        assert_eq!(view.key_absent(near_key), Absence::Proven);
        fs::write(dir.join(VIEW_FILE_NAME), "{").unwrap();
    }
    assert!(
        !asked.load(Ordering::SeqCst),
        "the local baseline was asked for"
    );
    // The edition of the host compares without case, as for the exact loader.
    let view = BaselineView::open(&dir, &HostOs::new("professional", 26300, 9974), || None);
    assert_eq!(view.trust(), BaselineTrust::Exact);
    let _ = fs::remove_dir_all(&dir);
}

/// Without the exact baseline: neighbours by the rule, unusable files skipped with a warning (a
/// local baseline under a shipped name included, L6), the local baseline from the caller.
#[test]
fn open_without_an_exact_baseline_merges() {
    let dir = temp_dir("open-merged");
    fs::write(dir.join(VIEW_FILE_NAME), SHIPPED_VIEW).unwrap();
    let near_key = r"HKLM\SOFTWARE\Classes\CLSID\{near}";
    let far_key = r"HKLM\SOFTWARE\Classes\CLSID\{far}";
    let local_key = r"HKLM\SOFTWARE\Classes\CLSID\{local}";
    write_shipped(&dir, "Professional", 26340, 9882, &[near_key]);
    write_shipped(&dir, "EnterpriseSEval", 26100, 1742, &[far_key]);
    write_shipped(
        &dir,
        "Professional",
        19045,
        5000,
        &[r"HKLM\SOFTWARE\Classes\CLSID\{w10}"],
    );
    // Header and name disagree: nearer than every good one, and skipped.
    fs::write(
        dir.join(Baseline::file_name("Professional", 26301, 1)),
        gzip(&shipped_text(
            "Professional",
            26302,
            1,
            &[r"HKLM\SOFTWARE\Classes\CLSID\{liar}"],
        )),
    )
    .unwrap();
    // A local baseline planted under a shipped name: refused by its header.
    let planted = encode(
        &local_header(&HostOs::new("Professional", 26299, 1)),
        &ok_sources(),
        &{
            let mut r = Records::new();
            r.add_key(r"HKLM\SOFTWARE\Classes\CLSID\{planted}");
            r
        },
    )
    .unwrap();
    fs::write(
        dir.join(Baseline::file_name("Professional", 26299, 1)),
        &planted.bytes,
    )
    .unwrap();
    // A local baseline under its own name is not a shipped file at all.
    fs::write(
        dir.join(crate::local_baseline::local_file_name(
            "Professional",
            26300,
            9974,
            "abc",
        )),
        &planted.bytes,
    )
    .unwrap();
    fs::write(dir.join("README.md"), "x").unwrap();

    let view = BaselineView::open(&dir, &host(), || Some(local(&host(), &[local_key])));
    assert_eq!(view.trust(), BaselineTrust::Merged, "{:?}", view.warnings());
    // The two unusable files were the best two; the next ones took their place.
    assert_eq!(
        view.neighbour_names(),
        ["Professional-26340.9882", "EnterpriseSEval-26100.1742"]
    );
    assert_eq!(view.name(), "local-Professional-26300.9974+2");
    for key in [near_key, far_key, local_key] {
        assert_eq!(view.key_absent(key), Absence::Present, "{key}");
    }
    for key in [
        r"HKLM\SOFTWARE\Classes\CLSID\{w10}",
        r"HKLM\SOFTWARE\Classes\CLSID\{liar}",
        r"HKLM\SOFTWARE\Classes\CLSID\{planted}",
    ] {
        assert_eq!(
            view.key_absent(key),
            Absence::Inferred(BaselineTrust::Merged),
            "{key}"
        );
    }
    let warnings = view.warnings();
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("Professional-26301.1.tsv.gz")),
        "{warnings:?}"
    );
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("Professional-26299.1.tsv.gz")),
        "{warnings:?}"
    );

    // Only names are read by the selection.
    let chosen = select_neighbours(&dir, &host(), shipped_rules().neighbours()).unwrap();
    let names: Vec<String> = chosen.iter().map(NeighbourFile::name).collect();
    assert_eq!(
        names,
        [
            "Professional-26299.1",
            "Professional-26301.1",
            "Professional-26340.9882"
        ]
    );

    // No local baseline: trust None, the neighbours still answer presence.
    let view = BaselineView::open(&dir, &host(), || None);
    assert_eq!(view.trust(), BaselineTrust::None);
    assert!(view.has_key(near_key));
    assert_eq!(view.key_absent(local_key), Absence::Unknown);

    // A refused view.json: the trust stands, no area is marked, and the warnings say so.
    fs::write(
        dir.join(VIEW_FILE_NAME),
        SHIPPED_VIEW.replace("purge.baseline-view/1", "x"),
    )
    .unwrap();
    let view = BaselineView::open(&dir, &host(), || Some(local(&host(), &[local_key])));
    assert_eq!(view.trust(), BaselineTrust::Merged);
    assert_eq!(view.key_absent(local_key), Absence::Present);
    assert_eq!(
        view.key_absent(r"HKLM\SOFTWARE\Classes\CLSID\{w10}"),
        Absence::Unknown
    );
    assert!(
        view.warnings().iter().any(|w| w.contains("view.json")),
        "{:?}",
        view.warnings()
    );

    // An exact-named file that is unusable is reported and is not a neighbour either.
    fs::write(dir.join(VIEW_FILE_NAME), SHIPPED_VIEW).unwrap();
    fs::write(
        dir.join(Baseline::file_name("Professional", 26300, 9974)),
        gzip(&shipped_text(
            "Professional",
            26300,
            1,
            &[r"HKLM\SOFTWARE\Classes\CLSID\{bad-exact}"],
        )),
    )
    .unwrap();
    let view = BaselineView::open(&dir, &host(), || Some(local(&host(), &[local_key])));
    assert_eq!(view.trust(), BaselineTrust::Merged);
    assert!(!view.has_key(r"HKLM\SOFTWARE\Classes\CLSID\{bad-exact}"));
    assert!(
        view.warnings()[0].contains("Professional-26300.9974.tsv.gz"),
        "{:?}",
        view.warnings()
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The shipped directory, for the host of the design: both shipped baselines are its neighbours.
#[test]
fn the_shipped_directory_gives_this_host_two_neighbours() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../kb/baselines");
    let rules = ViewRules::load(&dir).unwrap();
    let files = select_neighbours(&dir, &host(), rules.neighbours()).unwrap();
    let names: Vec<String> = files.iter().map(NeighbourFile::name).collect();
    assert_eq!(
        names,
        ["Professional-26340.9882", "EnterpriseSEval-26100.1742"]
    );
    // BL-RM S6: a retail host of the LTSC file's build gets the other shipped baseline too.
    let retail = HostOs::new("Professional", 26100, 4000);
    let files = select_neighbours(&dir, &retail, rules.neighbours()).unwrap();
    let names: Vec<String> = files.iter().map(NeighbourFile::name).collect();
    assert_eq!(
        names,
        ["EnterpriseSEval-26100.1742", "Professional-26340.9882"]
    );
    // On the baseline's own machine the file is the exact one and never its own neighbour.
    let clean_pro = HostOs::new("Professional", 26340, 9882);
    let files = select_neighbours(&dir, &clean_pro, rules.neighbours()).unwrap();
    let names: Vec<String> = files.iter().map(NeighbourFile::name).collect();
    assert_eq!(names, ["EnterpriseSEval-26100.1742"]);
}

// -------------------------------------------------------------------------------------------------
// Hashed sets (the input of a derived cache form)
// -------------------------------------------------------------------------------------------------

#[test]
fn hashed_sets_round_trip() {
    let rules = shipped_rules();
    let mut records = Records::new();
    records.add_key(r"HKLM\SOFTWARE\Classes\CLSID\{A}");
    records.add_value(r"HKLM\SOFTWARE\Classes\.txt", "Content Type", 1);
    records.add_file(r"C:\Windows\System32\a.dll");
    let mut sources = ok_sources();
    s3_facts(&mut sources, "1", r"HKU\.DEFAULT\Software\Sealed");
    let text_form = local_from(&host(), &sources, &records);
    let (header, lines) = (text_form.header().clone(), text_form.sources().to_vec());
    let counts = text_form.counts();
    let record_count = text_form.record_count();
    let sets = text_form.clone().into_hashed_sets();
    sets.check().unwrap();
    assert_eq!(sets.counts, counts);
    let hashed_form =
        LocalBaseline::from_hashed_sets(header.clone(), lines.clone(), sets.clone()).unwrap();
    assert_eq!(hashed_form.record_count(), record_count);
    assert_eq!(hashed_form.counts(), counts);
    assert_eq!(hashed_form.complete(), text_form.complete());
    assert_eq!(hashed_form.clone().into_hashed_sets(), sets);

    let synthetic = Baseline::from_bytes(SYNTHETIC.as_bytes()).unwrap();
    let near_host = HostOs::new("Synthetic", 12345, 1);
    let neighbour_sets = Neighbour::from_baseline(synthetic.clone()).into_hashed_sets();
    let rebuilt =
        Neighbour::from_hashed_sets("Synthetic", 12345, 678, neighbour_sets.clone()).unwrap();
    assert_eq!(rebuilt.name(), "Synthetic-12345.678");
    assert_eq!(rebuilt.counts(), synthetic.counts());
    let view = BaselineView::assemble(&near_host, None, vec![rebuilt], &rules);
    assert_presence_equals(&view, &synthetic, "a neighbour from hashed sets");

    // The view over the hashed form answers as the view over the parsed text.
    let near = || vec![neighbour("Professional", 26340, 9882, &[])];
    let from_text = BaselineView::merged(&host(), text_form, near(), &rules);
    let from_sets = BaselineView::merged(&host(), hashed_form, near(), &rules);
    assert_eq!(from_sets.trust(), BaselineTrust::Merged);
    assert_eq!(from_sets.name(), from_text.name());
    assert_eq!(from_sets.local_id(), from_text.local_id());
    for key in [
        r"HKLM\SOFTWARE\Classes\CLSID\{A}",
        r"HKLM\SOFTWARE\Classes\CLSID\{B}",
        r"HKLM\SOFTWARE\Classes\.txt",
        r"HKLM\SOFTWARE\Classes",
        r"HKU\.DEFAULT\Software\Sealed\x",
    ] {
        assert_eq!(
            from_sets.key_absent(key),
            from_text.key_absent(key),
            "{key}"
        );
        assert_eq!(
            from_sets.has_value(key, "content type"),
            from_text.has_value(key, "content type")
        );
    }
    assert!(from_sets.has_value(r"HKLM\SOFTWARE\Classes\.txt", "content type"));
    assert!(from_sets.has_path(r"C:\Windows\System32\a.dll"));
    assert!(from_sets.has_token("a"));

    // Refused: sets out of order or with a duplicate, and another builder's header.
    let mut unsorted = sets.clone();
    unsorted.keys.reverse();
    assert!(unsorted.keys.len() > 1);
    assert!(
        LocalBaseline::from_hashed_sets(header.clone(), lines.clone(), unsorted.clone()).is_err()
    );
    assert!(Neighbour::from_hashed_sets("X", 1, 2, unsorted).is_err());
    let mut doubled = sets.clone();
    doubled.leaves.push(*doubled.leaves.last().unwrap());
    assert_eq!(doubled.check().unwrap_err().set, "leaves");
    assert!(LocalBaseline::from_hashed_sets(header.clone(), lines.clone(), doubled).is_err());
    let mut old = header;
    old.builder_version = "bl.0".into();
    assert!(LocalBaseline::from_hashed_sets(old, lines, sets).is_err());
    HashedSets::default().check().unwrap();

    // The scheme names this build's normalisation and hash; it is the same on every call.
    let scheme = HashedSets::scheme();
    assert!(
        scheme.starts_with("fnv1a64-") && scheme.len() == 24,
        "{scheme}"
    );
    assert_eq!(scheme, HashedSets::scheme());
}

/// The load of the view on this machine, for the budget of design §5 (1.5 s warm, local plus
/// neighbours). Not run by default: set `PURGE_BL_LOCAL_FILE` to a file written by
/// `purge-engine baseline build` and run with `--release --ignored --nocapture`.
#[test]
#[ignore = "a measurement; needs PURGE_BL_LOCAL_FILE"]
fn view_load_time_on_this_host() {
    use std::time::Instant;
    let file = PathBuf::from(std::env::var_os("PURGE_BL_LOCAL_FILE").expect("PURGE_BL_LOCAL_FILE"));
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../kb/baselines");
    let mut best = [f64::MAX; 6];
    let mut keep = |slot: usize, t: Instant| {
        let s = t.elapsed().as_secs_f64();
        best[slot] = best[slot].min(s);
        s
    };
    for run in 0..3 {
        let t = Instant::now();
        let lb = LocalBaseline::load(&file).expect("the local baseline loads");
        let local_text = keep(0, t);
        let h = lb.header();
        let os = HostOs::new(&h.edition, h.build, h.ubr);
        let rules = ViewRules::load(&dir).unwrap();

        let t = Instant::now();
        let mut warnings = Vec::new();
        let neighbours = load_neighbours(&dir, &os, rules.neighbours(), &mut warnings);
        let neighbours_text = keep(1, t);
        let names: Vec<String> = neighbours.iter().map(Neighbour::name).collect();

        // The whole view from the text files, the local one read beside the neighbours.
        let t = Instant::now();
        let view = BaselineView::open(&dir, &os, || LocalBaseline::load(&file).ok());
        let open_text = keep(2, t);

        // The same parts from their hashed sets, as a derived cache form would hand them over
        // (without the cache's own file read).
        let (header, sources) = (lb.header().clone(), lb.sources().to_vec());
        let counts = lb.counts();
        let local_sets = lb.into_hashed_sets();
        let neighbour_sets: Vec<_> = neighbours
            .into_iter()
            .map(|n| {
                (
                    n.edition().to_owned(),
                    n.build(),
                    n.ubr(),
                    n.into_hashed_sets(),
                )
            })
            .collect();
        let bytes = |s: &HashedSets| {
            8 * (s.keys.len()
                + s.values.len()
                + s.dirs.len()
                + s.files.len()
                + s.leaves.len()
                + s.parts.len())
        };
        let set_bytes: usize =
            bytes(&local_sets) + neighbour_sets.iter().map(|n| bytes(&n.3)).sum::<usize>();
        let t = Instant::now();
        let lb = LocalBaseline::from_hashed_sets(header, sources, local_sets).unwrap();
        let ns: Vec<Neighbour> = neighbour_sets
            .into_iter()
            .map(|(e, b, u, s)| Neighbour::from_hashed_sets(&e, b, u, s).unwrap())
            .collect();
        let from_sets = BaselineView::assemble(&os, Some(lb), ns, &rules);
        let assemble = keep(3, t);
        assert_eq!(from_sets.trust(), view.trust());
        assert_eq!(from_sets.name(), view.name());

        println!(
            "run {run}: host {} | local text {local_text:.3} s ({} K, {} V, {} D, {} F) | \
             neighbours {names:?} text {neighbours_text:.3} s | open (text, parallel) {open_text:.3} s \
             | from hashed sets {assemble:.3} s ({:.1} MB of sets) | trust {} name {} | {:?}",
            os.name(),
            counts.keys,
            counts.values,
            counts.dirs,
            counts.files,
            set_bytes as f64 / 1e6,
            view.trust(),
            view.name(),
            view.warnings(),
        );
    }
    println!(
        "best of 3: local text {:.3} s, neighbours text {:.3} s, open {:.3} s, from hashed sets {:.3} s",
        best[0], best[1], best[2], best[3]
    );
}
