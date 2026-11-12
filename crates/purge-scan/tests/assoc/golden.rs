//! Golden files: a stable text rendering of scanner output, compared with `tests/assoc/golden/<name>.txt`.
//!
//! Run the tests with `PURGE_BLESS=1` to (re)write the files after an intended change, then review the
//! diff.

use std::fmt::Write as _;
use std::path::PathBuf;

use purge_model::{Candidate, Target};

/// One line for a target.
pub fn target_text(target: &Target) -> String {
    match target {
        Target::RegKey { path } => format!("RegKey {path}"),
        Target::RegValue { path, name } => format!("RegValue {path} | {name:?}"),
        Target::RegMultiSzSegment {
            path,
            name,
            segment,
            index,
        } => format!("Segment {path} | {name:?} | {segment:?} @ {index:?}"),
        other => format!("{other:?}"),
    }
}

/// The candidates as text: everything a scanner sets, one block per candidate, in emission order.
pub fn render(candidates: &[Candidate]) -> String {
    let mut out = String::new();
    for c in candidates {
        writeln!(
            out,
            "[{}] {:?} {}",
            c.scanner,
            c.action,
            target_text(&c.target)
        )
        .unwrap();
        writeln!(
            out,
            "  id={} category={:?} harm={:?} reversibility={:?} origin={:?} child_count={:?}",
            c.id.0, c.category, c.harm, c.reversibility, c.origin, c.child_count
        )
        .unwrap();
        for child in &c.children {
            writeln!(out, "  child {}", child.0).unwrap();
        }
        for e in &c.evidence {
            let detail: Vec<String> = e.detail.0.iter().map(|(k, v)| format!("{k}={v}")).collect();
            writeln!(
                out,
                "  evidence {:?} {:?}/{} {:?} {:?} source={}",
                e.kind, e.tier, e.weight, e.scope, e.trust, e.source.0
            )
            .unwrap();
            for line in detail {
                writeln!(out, "    {line}").unwrap();
            }
        }
        for b in &c.blockers {
            writeln!(out, "  blocker {b:?}").unwrap();
        }
        assert!(c.decision.is_none(), "a scanner never decides a band");
    }
    out
}

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("assoc")
        .join("golden")
        .join(format!("{name}.txt"))
}

/// Compares the rendering of `candidates` with the golden file `name`.
pub fn check(name: &str, candidates: &[Candidate]) {
    let actual = render(candidates);
    let path = golden_path(name);
    if std::env::var_os("PURGE_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| {
            panic!(
                "cannot read {}: {e} (run with PURGE_BLESS=1)",
                path.display()
            )
        })
        .replace("\r\n", "\n");
    assert!(
        expected == actual,
        "golden {name} differs.\n--- expected\n{expected}\n--- actual\n{actual}"
    );
}
