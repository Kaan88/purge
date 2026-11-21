//! Views below Exact for tests of the crates that consume a [`BaselineView`] (scan, harvest, replay).
//! Everything is built through the real doors: a shipped baseline from its text, a local baseline
//! through the file format, the view through [`BaselineView::assemble`].

use super::{BaselineView, HostOs, Neighbour, VIEW_SCHEMA, ViewRules};
use crate::baseline::Baseline;
use crate::local_baseline::file::encode;
use crate::local_baseline::{
    BUILDER_VERSION, LocalBaseline, LocalHeader, LocalSource, Records, SourceLine, SourceStatus,
};

/// Rules that accept inferred absence everywhere a key can be bound (`HKLM`, `HKU`), at trust Merged
/// and at trust Local: the most permissive `view.json` there can be. A view made with them answers
/// `Inferred` for every in-scope key no set has, so a consumer that stays capped under these rules is
/// capped under any.
pub fn open_rules() -> ViewRules {
    ViewRules::parse(&format!(
        "{{\"schema\":\"{VIEW_SCHEMA}\",\"neighbours\":{{\"max_build_distance\":1000,\"max_count\":3}},\
         \"areas\":[{{\"id\":\"all\",\"title\":\"all\",\"prefixes\":[\"hklm\",\"hku\"],\
         \"merged\":true,\"local\":true}}]}}"
    ))
    .expect("the open test rules parse")
}

/// One entry of a fixture's `keys`.
enum Entry<'a> {
    Key(&'a str),
    Value(&'a str, &'a str),
    Dir(&'a str),
    File(&'a str),
}

/// The entry of a fixture's `keys` for the value `name` of `key` (`""`: the default value). A shipped
/// baseline then has the value and not, by that entry alone, the key; a local baseline records the
/// key with every value.
pub fn value_entry(key: &str, name: &str) -> String {
    format!("V\t{key}\t{name}")
}

/// The entry of a fixture's `keys` for a file; a bare drive path (`C:\…`) is a directory.
pub fn file_entry(path: &str) -> String {
    format!("F\t{path}")
}

/// Reads an entry: [`value_entry`], [`file_entry`], a directory for a drive path (`C:\…`), else a
/// registry key.
fn entry(text: &str) -> Entry<'_> {
    if let Some(value) = text.strip_prefix("V\t") {
        let (key, name) = value
            .split_once('\t')
            .expect("a value entry is V, key, name");
        return Entry::Value(key, name);
    }
    if let Some(path) = text.strip_prefix("F\t") {
        return Entry::File(path);
    }
    let b = text.as_bytes();
    if b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\' {
        Entry::Dir(text)
    } else {
        Entry::Key(text)
    }
}

/// A shipped baseline of (`edition`, `build`.`ubr`) holding `keys`: registry keys, directories for
/// the entries spelled as a drive path (`C:\…`), values ([`value_entry`]) and files ([`file_entry`]).
pub fn shipped(edition: &str, build: u32, ubr: u32, keys: &[&str]) -> Baseline {
    let mut text = format!("#purge-baseline 1\tT\tPC\t{edition}\t{build}.{ubr}\n");
    let escaped = |field: &str| {
        field
            .replace('\\', "\\\\")
            .replace('\t', "\\t")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\0', "\\0")
    };
    for key in keys {
        match entry(key) {
            Entry::Key(key) => text.push_str(&format!("K\t{}\t0\t0\t0\n", escaped(key))),
            Entry::Value(key, name) => text.push_str(&format!(
                "V\t{}\t{}\t1\t0000000000000000\n",
                escaped(key),
                escaped(name)
            )),
            Entry::Dir(path) => text.push_str(&format!("D\t{}\n", escaped(path))),
            Entry::File(path) => text.push_str(&format!("F\t{}\n", escaped(path))),
        }
    }
    Baseline::from_bytes(text.as_bytes()).expect("the test baseline parses")
}

/// A complete local baseline of (`edition`, `build`.`ubr`) holding `keys` (the entries of
/// [`shipped`]).
pub fn local(edition: &str, build: u32, ubr: u32, keys: &[&str]) -> LocalBaseline {
    let mut records = Records::new();
    for key in keys {
        match entry(key) {
            Entry::Key(key) => records.add_key(key),
            Entry::Value(key, name) => records.add_value(key, name, 1),
            Entry::Dir(path) => records.add_dir(path),
            Entry::File(path) => records.add_file(path),
        };
    }
    let sources: Vec<SourceLine> = LocalSource::REQUIRED
        .map(|source| SourceLine {
            source,
            status: SourceStatus::Ok,
            items: 1,
            records: 1,
            skipped: 0,
            reasons: Vec::new(),
            facts: Vec::new(),
        })
        .to_vec();
    let header = LocalHeader {
        built_at: "2026-11-21T00:00:00Z".into(),
        computer: "PC".into(),
        edition: edition.to_owned(),
        build,
        ubr,
        builder_version: BUILDER_VERSION.into(),
        source_id: "0123456789abcdef".into(),
    };
    let enc = encode(&header, &sources, &records).expect("the test local baseline encodes");
    LocalBaseline::from_bytes(&enc.bytes).expect("the test local baseline reads back")
}

/// How many baselines [`below_exact`] has.
pub const BELOW_EXACT: usize = 4;

/// The `which`-th of the baselines a scan or harvest of the Windows `os` can have below Exact, each
/// holding no record at all: `0` no baseline (`None`), `1` a Merged view, `2` a Local view, `3` a view of
/// trust None with a neighbour. The views use [`open_rules`], so they would infer absence for every
/// in-scope key; a presence-only consumer must treat all four alike.
pub fn below_exact(which: usize, os: &purge_model::OsInfo) -> Option<BaselineView> {
    let (edition, build, ubr) = (os.edition.as_str(), os.build, os.ubr);
    match which {
        0 => None,
        1 => Some(merged_view(edition, build, ubr, &[], &[])),
        2 => Some(local_view(edition, build, ubr, &[])),
        3 => Some(none_view(edition, build, ubr, &[])),
        _ => panic!("below_exact: {which} is not below {BELOW_EXACT}"),
    }
}

/// A view of trust **Merged** for the host (`edition`, `build`.`ubr`): a complete local baseline
/// holding `local_keys`, one shipped neighbour (the next build, same edition) holding
/// `neighbour_keys`, and [`open_rules`].
pub fn merged_view(
    edition: &str,
    build: u32,
    ubr: u32,
    local_keys: &[&str],
    neighbour_keys: &[&str],
) -> BaselineView {
    let host = HostOs::new(edition, build, ubr);
    let neighbour = Neighbour::from_baseline(shipped(edition, build + 1, ubr, neighbour_keys));
    let view = BaselineView::merged(
        &host,
        local(edition, build, ubr, local_keys),
        vec![neighbour],
        &open_rules(),
    );
    assert_eq!(view.trust(), super::BaselineTrust::Merged, "{view:?}");
    view
}

/// A view of trust **Local** for the host: a complete local baseline holding `keys` and
/// [`open_rules`], no neighbour.
pub fn local_view(edition: &str, build: u32, ubr: u32, keys: &[&str]) -> BaselineView {
    let host = HostOs::new(edition, build, ubr);
    let view = BaselineView::local(&host, local(edition, build, ubr, keys), &open_rules());
    assert_eq!(view.trust(), super::BaselineTrust::Local, "{view:?}");
    view
}

/// A view of trust **None** for the host that still holds one shipped neighbour (the next build) with
/// `keys`: presence only.
pub fn none_view(edition: &str, build: u32, ubr: u32, keys: &[&str]) -> BaselineView {
    let host = HostOs::new(edition, build, ubr);
    let neighbour = Neighbour::from_baseline(shipped(edition, build + 1, ubr, keys));
    let view = BaselineView::none(&host, None, vec![neighbour], &open_rules());
    assert_eq!(view.trust(), super::BaselineTrust::None, "{view:?}");
    view
}
