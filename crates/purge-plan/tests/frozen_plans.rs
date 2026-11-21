//! Replay of the frozen M1b scan documents (M3-ENGINE-OUT).
//!
//! The scan gate's evidence under `vm/truth/m1b-evidence/` holds complete `purge.scan/0` documents
//! with the plan hash each scan produced. These are committed, so this replay needs no VM: every
//! stored hash must still be the hash of the document's own items under its stored policy version and
//! mode. The M3 display fields (`display_name`, `owner_program`) are outside the hash; a document
//! without them (all frozen ones) reads and hashes exactly as it did when it was written.

use std::fs;
use std::path::Path;

use purge_model::Candidate;
use purge_plan::emit::ScanDoc;
use purge_plan::hash::plan_hash;

/// The committed scan-gate evidence: one `<id>-scan.json` per scan.
fn evidence_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vm/truth/m1b-evidence")
}

fn scan_documents() -> Vec<(String, ScanDoc)> {
    let dir = evidence_dir();
    let entries = fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!(
            "{} is part of the repository, but it could not be read: {e}",
            dir.display()
        )
    });
    let mut documents = Vec::new();
    for entry in entries {
        let path = entry.expect("a readable evidence entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !name.ends_with("-scan.json") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let doc: ScanDoc = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{} is not a purge.scan/0 document: {e}", path.display()));
        documents.push((name.to_owned(), doc));
    }
    documents.sort_by(|a, b| a.0.cmp(&b.0));
    documents
}

/// Every frozen M1b plan hash is unchanged: it is still the hash of the document's own items, policy
/// version and mode. The display fields added for the UI are none of those.
#[test]
fn frozen_m1b_plan_hashes_are_unchanged() {
    let documents = scan_documents();
    assert!(
        documents.len() >= 18,
        "the M1b evidence holds 18 scan documents, found {}",
        documents.len()
    );
    for (name, doc) in &documents {
        assert_eq!(
            plan_hash(&doc.items, &doc.policy_version, doc.mode),
            doc.plan_hash,
            "{name}: the plan hash changed"
        );
        // The frozen documents predate the display fields: they read as absent.
        assert!(
            doc.items
                .iter()
                .chain(&doc.absorbed)
                .all(|c| c.display_name.is_none() && c.owner_program.is_none()),
            "{name}: a frozen item carries an M3 display field"
        );
    }
}

/// The display fields are outside the hash on the frozen documents too: setting them on every item
/// leaves the stored hash.
#[test]
fn display_fields_change_no_frozen_plan_hash() {
    for (name, doc) in scan_documents() {
        let mut items: Vec<Candidate> = doc.items.clone();
        for (i, item) in items.iter_mut().enumerate() {
            item.display_name = Some(format!("Object {i}"));
            item.owner_program = Some(format!(r"C:\Program Files\Vendor\app{i}.exe"));
        }
        assert_eq!(
            plan_hash(&items, &doc.policy_version, doc.mode),
            doc.plan_hash,
            "{name}: a display field entered the plan hash"
        );
    }
}
