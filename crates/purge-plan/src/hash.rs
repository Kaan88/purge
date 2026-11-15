//! The plan hash (ENGINE_PLAN.md §7.1): SHA-256 over the canonical JSON of the ordered items, the policy
//! version and the scan mode. It is what the consent dialog shows and what the executor checks (M2).
//!
//! # What is hashed
//!
//! [`canonical_plan_json`] builds this document and [`plan_hash`] hashes its UTF-8 bytes:
//!
//! ```json
//! {"items":[{"action":"DeleteKey","band":"Safe","category":"Registration","children":["c-2"],
//!            "id":"c-1","preselected":true,"scanner":"REG-SOFTWARE",
//!            "target":{"path":"HKLM\\SOFTWARE\\Vendor\\App","type":"RegKey"}}],
//!  "mode":"post","policy":"m1a.2","schema":"purge.planhash/0"}
//! ```
//!
//! Items are taken in the order given (the plan order of [`crate::order`]), so reordering changes the
//! hash. Per item the hash covers what would be done and how it was judged: target, action, band,
//! preselection, scanner, category, id, and the ids of absorbed children. Scores and explanation texts are
//! left out: they follow from the evidence and the policy version, which is hashed. The scan-time identity
//! of a path item (`Candidate::item_fp`) is left out too (decided for M2, so that every M1a plan hash stays
//! valid): it can only make the executor refuse or skip an item, never act on more.
//!
//! # Canonical JSON
//!
//! [`canonical_json`] writes a `serde_json::Value` with object keys sorted by their UTF-8 bytes, no
//! whitespace, and strings and numbers exactly as `serde_json` writes them. The sorting is done here, so
//! the result does not depend on whether `serde_json` was built with `preserve_order`.

use purge_model::{Candidate, ScanMode};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// The `schema` value of the hashed document. Changing what is hashed changes this id.
pub const HASH_SCHEMA: &str = "purge.planhash/0";

/// Writes `value` as canonical JSON (see the module docs).
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write_canonical(&map[key], out);
            }
            out.push('}');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// A model value as JSON. The model types serialise without failing; `null` stands in if one ever did, so
/// that the hash changes rather than the engine stopping.
fn to_value<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

fn item_value(candidate: &Candidate) -> Value {
    let decision = candidate.decision.as_ref();
    let mut item = Map::new();
    item.insert("action".into(), to_value(&candidate.action));
    item.insert(
        "band".into(),
        decision.map_or(Value::Null, |d| to_value(&d.band)),
    );
    item.insert("category".into(), to_value(&candidate.category));
    item.insert("children".into(), to_value(&candidate.children));
    item.insert("id".into(), to_value(&candidate.id));
    item.insert(
        "preselected".into(),
        Value::Bool(decision.is_some_and(|d| d.preselected)),
    );
    item.insert("scanner".into(), Value::String(candidate.scanner.clone()));
    item.insert("target".into(), to_value(&candidate.target));
    Value::Object(item)
}

/// The canonical JSON document the plan hash is computed over.
#[must_use]
pub fn canonical_plan_json(items: &[Candidate], policy_version: &str, mode: ScanMode) -> String {
    let doc = json!({
        "schema": HASH_SCHEMA,
        "policy": policy_version,
        "mode": to_value(&mode),
        "items": items.iter().map(item_value).collect::<Vec<_>>(),
    });
    canonical_json(&doc)
}

/// The plan hash: lower-case hex SHA-256 of [`canonical_plan_json`].
///
/// `items` are the top-level items of the plan in plan order; `policy_version` is
/// `purge_policy::band::POLICY_VERSION` for plans this engine builds.
#[must_use]
pub fn plan_hash(items: &[Candidate], policy_version: &str, mode: ScanMode) -> String {
    let digest = Sha256::digest(canonical_plan_json(items, policy_version, mode).as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(byte & 0xf), 16).unwrap_or('0'));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decide::testkit::*;
    use purge_model::{Action, Band, CandidateId, Category, Decision};

    fn decided(mut c: Candidate, band: Band, preselected: bool) -> Candidate {
        c.decision = Some(Decision {
            band,
            preselected,
            score: 9,
            explanation: "because".into(),
        });
        c
    }

    fn items() -> Vec<Candidate> {
        let mut parent = decided(
            cand("c-1", key(r"HKLM\SOFTWARE\Vendor\App"), "REG-SOFTWARE"),
            Band::Safe,
            true,
        );
        parent.children.push(CandidateId("c-2".into()));
        let value = decided(
            cand(
                "c-3",
                value(r"HKU\S-1-5-21-1\Software\Vendor", ""),
                "REF-ANY",
            ),
            Band::Likely,
            false,
        );
        let mut file = decided(
            cand(
                "c-4",
                path("C:\\Users\\t\\\u{e9}t\u{e9} \"q\".lnk"),
                "FS-SHORTCUTS",
            ),
            Band::Blocked,
            false,
        );
        file.category = Category::AppFiles;
        vec![parent, value, file]
    }

    const GOLDEN_JSON: &str = concat!(
        r#"{"items":["#,
        r#"{"action":"DeleteKey","band":"Safe","category":"Registration","children":["c-2"],"id":"c-1","#,
        r#""preselected":true,"scanner":"REG-SOFTWARE","target":{"path":"HKLM\\SOFTWARE\\Vendor\\App","type":"RegKey"}},"#,
        r#"{"action":"DeleteValue","band":"Likely","category":"Registration","children":[],"id":"c-3","#,
        r#""preselected":false,"scanner":"REF-ANY","target":{"name":"","path":"HKU\\S-1-5-21-1\\Software\\Vendor","type":"RegValue"}},"#,
        r#"{"action":"Quarantine","band":"Blocked","category":"AppFiles","children":[],"id":"c-4","#,
        r#""preselected":false,"scanner":"FS-SHORTCUTS","target":{"path":"C:\\Users\\t\\été \"q\".lnk","type":"Path"}}"#,
        r#"],"mode":"post","policy":"m1a.2","schema":"purge.planhash/0"}"#,
    );

    /// SHA-256 of `GOLDEN_JSON` as UTF-8, computed independently (Python `hashlib`).
    const GOLDEN_HASH: &str = "10e9da8690be9214c32b5379a6688586b78ff5b221b3877b2f59cfefc3f149b2";

    #[test]
    fn golden() {
        let items = items();
        assert_eq!(
            canonical_plan_json(&items, "m1a.2", ScanMode::Post),
            GOLDEN_JSON
        );
        assert_eq!(plan_hash(&items, "m1a.2", ScanMode::Post), GOLDEN_HASH);
        // Stable across calls.
        assert_eq!(
            plan_hash(&items, "m1a.2", ScanMode::Post),
            plan_hash(&items.clone(), "m1a.2", ScanMode::Post)
        );
    }

    /// `item_fp` is not hashed (decided for M2): a plan whose path items carry their scan-time identity
    /// has the golden document and hash of the same plan without it.
    #[test]
    fn item_fp_does_not_enter_the_hash() {
        use purge_model::exec::op::FileIdHex;
        let mut items = items();
        assert!(items.iter().all(|c| c.item_fp.is_none()));
        let file = items
            .iter_mut()
            .find(|c| matches!(c.target, purge_model::Target::Path { .. }))
            .unwrap();
        file.set_item_fp(FileIdHex([0xab; 16]), u64::MAX);
        assert!(file.item_fp.is_some());
        assert_eq!(
            canonical_plan_json(&items, "m1a.2", ScanMode::Post),
            GOLDEN_JSON
        );
        assert_eq!(plan_hash(&items, "m1a.2", ScanMode::Post), GOLDEN_HASH);
        // Another identity, same hash: the executor checks the identity, the hash does not.
        let mut other = items.clone();
        other[2].set_item_fp(FileIdHex([1; 16]), 7);
        assert_eq!(plan_hash(&other, "m1a.2", ScanMode::Post), GOLDEN_HASH);
    }

    #[test]
    fn empty_plan_has_a_hash_too() {
        assert_eq!(
            canonical_plan_json(&[], "m1a.2", ScanMode::Forced),
            r#"{"items":[],"mode":"forced","policy":"m1a.2","schema":"purge.planhash/0"}"#
        );
        let hash = plan_hash(&[], "m1a.2", ScanMode::Forced);
        assert_eq!(hash.len(), 64);
        assert!(
            hash.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }

    #[test]
    fn any_change_changes_the_hash() {
        let base = items();
        let reference = plan_hash(&base, "m1a.2", ScanMode::Post);
        let mut seen = vec![reference.clone()];
        let mut check = |label: &str, hash: String| {
            assert!(!seen.contains(&hash), "{label} did not change the hash");
            seen.push(hash);
        };
        check("policy version", plan_hash(&base, "m1a.3", ScanMode::Post));
        check("mode", plan_hash(&base, "m1a.2", ScanMode::External));
        check(
            "dropped item",
            plan_hash(&base[..2], "m1a.2", ScanMode::Post),
        );
        let mut reordered = base.clone();
        reordered.swap(0, 1);
        check("order", plan_hash(&reordered, "m1a.2", ScanMode::Post));

        type Edit = fn(&mut Candidate);
        let edits: [(&str, Edit); 9] = [
            ("band", |c| c.decision.as_mut().unwrap().band = Band::Likely),
            ("preselected", |c| {
                c.decision.as_mut().unwrap().preselected = false
            }),
            ("undecided", |c| c.decision = None),
            ("target", |c| c.target = key(r"HKLM\SOFTWARE\Vendor\App2")),
            ("target type", |c| {
                c.target = path(r"HKLM\SOFTWARE\Vendor\App")
            }),
            ("action", |c| c.action = Action::RemoveDirIfEmpty),
            ("category", |c| c.category = Category::ShellCom),
            ("scanner", |c| c.scanner = "REF-ANY".into()),
            ("children", |c| c.children.clear()),
        ];
        for (label, edit) in edits {
            let mut changed = base.clone();
            edit(&mut changed[0]);
            check(label, plan_hash(&changed, "m1a.2", ScanMode::Post));
        }
        // What is deliberately not hashed.
        let mut same = base.clone();
        let d = same[0].decision.as_mut().unwrap();
        d.explanation = "other words".into();
        d.score = 1;
        assert_eq!(plan_hash(&same, "m1a.2", ScanMode::Post), reference);
    }

    #[test]
    fn canonical_json_sorts_keys_at_every_level() {
        let v: Value = serde_json::from_str(
            r#"{"b":[{"z":1,"a":null},true,1.5],"a":{"y":"\u0001\n","x":-2},"":"é"}"#,
        )
        .unwrap();
        assert_eq!(
            canonical_json(&v),
            r#"{"":"é","a":{"x":-2,"y":"\u0001\n"},"b":[{"a":null,"z":1},true,1.5]}"#
        );
    }
}
